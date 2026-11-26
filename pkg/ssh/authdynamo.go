// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/crypto/ssh"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
)

const (
	defaultDynamoRefreshInterval = 10 * time.Minute
	// ponytail: an unknown key triggers a full table reload at most this
	// often. Unregistered cubes retry constantly, so every miss window
	// costs one scan (~3k read units for 48k items): 5m is ~$8/month worst
	// case, 1m would be ~$40. Make it configurable if onboarding needs to
	// be faster.
	dynamoMissRefreshInterval = 5 * time.Minute
	dynamoScanTimeout         = 2 * time.Minute
)

// keyScanner returns the full keyset: marshaled public key -> username.
type keyScanner func(ctx context.Context) (map[string]string, error)

// AuthorizedKeysDynamo serves SSH public key lookups from an in-memory
// snapshot of a DynamoDB table. Logins never wait on DynamoDB: the
// snapshot is reloaded in the background on a timer and after unknown
// keys. If the first load fails, frps still starts and keeps retrying;
// until a load succeeds every key is rejected.
type AuthorizedKeysDynamo struct {
	keys atomic.Pointer[map[string]string]
	scan keyScanner

	missInterval    time.Duration
	lastMissRefresh atomic.Int64 // unix nanos
	refreshMu       sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

func NewAuthorizedKeysDynamo(ctx context.Context, cfg v1.AuthorizedKeysDynamoDBConfig) (*AuthorizedKeysDynamo, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := dynamodb.NewFromConfig(awsCfg)

	interval := defaultDynamoRefreshInterval
	if cfg.RefreshIntervalSeconds > 0 {
		interval = time.Duration(cfg.RefreshIntervalSeconds) * time.Second
	}
	scan := func(ctx context.Context) (map[string]string, error) {
		return scanDynamoKeys(ctx, client, cfg.Table)
	}
	return newAuthorizedKeysDynamo(scan, interval, dynamoMissRefreshInterval), nil
}

func newAuthorizedKeysDynamo(scan keyScanner, interval, missInterval time.Duration) *AuthorizedKeysDynamo {
	ctx, cancel := context.WithCancel(context.Background())
	a := &AuthorizedKeysDynamo{scan: scan, missInterval: missInterval, ctx: ctx, cancel: cancel}
	empty := map[string]string{}
	a.keys.Store(&empty)
	go a.run(interval)
	return a
}

func (a *AuthorizedKeysDynamo) run(interval time.Duration) {
	// First load: retry with backoff instead of failing frps startup.
	for backoff := 5 * time.Second; a.refresh() != nil; backoff = min(backoff*2, interval) {
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(backoff):
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			_ = a.refresh()
		}
	}
}

func (a *AuthorizedKeysDynamo) refresh() error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	ctx, cancel := context.WithTimeout(a.ctx, dynamoScanTimeout)
	defer cancel()
	keys, err := a.scan(ctx)
	if err != nil {
		log.Warnf("authorized keys dynamodb reload failed, keeping %d cached keys: %v", len(*a.keys.Load()), err)
		return err
	}
	a.keys.Store(&keys)
	log.Infof("authorized keys dynamodb: loaded %d keys", len(keys))
	return nil
}

// LookupUser has the same contract as AuthorizedKeysDB.LookupUser.
func (a *AuthorizedKeysDynamo) LookupUser(_ context.Context, pubKeyBlob []byte) (string, bool, error) {
	if user, ok := (*a.keys.Load())[string(pubKeyBlob)]; ok {
		return user, true, nil
	}
	a.refreshAfterMiss()
	return "", false, nil
}

// refreshAfterMiss reloads in the background, at most once per missInterval.
// The rejected client retries on its own and gets in after the reload.
func (a *AuthorizedKeysDynamo) refreshAfterMiss() {
	now := time.Now().UnixNano()
	last := a.lastMissRefresh.Load()
	if now-last < int64(a.missInterval) || !a.lastMissRefresh.CompareAndSwap(last, now) {
		return
	}
	go func() { _ = a.refresh() }()
}

func (a *AuthorizedKeysDynamo) Close() {
	if a != nil {
		a.cancel()
	}
}

func scanDynamoKeys(ctx context.Context, client *dynamodb.Client, table string) (map[string]string, error) {
	keys := make(map[string]string, 50000)
	skipped := 0
	p := dynamodb.NewScanPaginator(client, &dynamodb.ScanInput{
		TableName:                aws.String(table),
		ProjectionExpression:     aws.String("#p, #u"),
		ExpressionAttributeNames: map[string]string{"#p": "pub", "#u": "mac"},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		for _, item := range page.Items {
			blob, user, ok := parseKeyItem(stringAttr(item, "pub"), stringAttr(item, "mac"))
			if !ok {
				skipped++
				continue
			}
			keys[blob] = user
		}
	}
	if skipped > 0 {
		log.Warnf("authorized keys dynamodb: skipped %d items without a valid pub/mac", skipped)
	}
	return keys, nil
}

func stringAttr(item map[string]types.AttributeValue, name string) string {
	if v, ok := item[name].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

// parseKeyItem turns a stored OpenSSH public key into the marshaled form the
// SSH callback sees. Stored values may be wrapped in quotes or whitespace.
func parseKeyItem(pub, user string) (blob, username string, ok bool) {
	pub = strings.TrimSpace(strings.Trim(strings.TrimSpace(pub), `"`))
	user = strings.TrimSpace(user)
	if pub == "" || user == "" {
		return "", "", false
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		return "", "", false
	}
	return string(key.Marshal()), user, true
}
