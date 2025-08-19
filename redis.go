package main

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var ctx = context.Background()
var redisClient *redis.Client

// 初始化 Redis 连接
func InitRedis(addr, password string, db int) error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// 主动 ping 一下 Redis，确认连接是否成功
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		return err // 连接失败，返回错误
	}

	logger.Info("Redis 连接成功", zap.String("addr", addr))
	return nil // 成功
}

// 1. 判断账户是否被锁定
func IsUserLocked(user string) (bool, error) {
	lockKey := fmt.Sprintf("黑名单:%s", user)
	locked, err := redisClient.Exists(ctx, lockKey).Result()
	if err != nil {
		return false, err
	}
	return locked > 0, nil
}

// 2. 登录失败计数 +1（并在超过阈值时锁定用户）
func RecordLoginFailure(user string, maxFails int, failTTL, lockTTL time.Duration) (int64, bool, error) {
	failKey := fmt.Sprintf("登录错误次数:%s", user)
	lockKey := fmt.Sprintf("黑名单:%s", user)

	// 增加失败计数
	fails, err := redisClient.Incr(ctx, failKey).Result()
	if err != nil {
		return 0, false, err
	}

	if fails == 1 {
		// 第一次失败，设置计数过期时间
		redisClient.Expire(ctx, failKey, failTTL)
	}

	if fails >= int64(maxFails) {
		// 超过失败次数 -> 锁定
		redisClient.Set(ctx, lockKey, 1, lockTTL)
		redisClient.Del(ctx, failKey)
		return fails, true, nil
	}

	return fails, false, nil
}

// 解锁用户
func UnlockUser(user string) error {
	lockKey := fmt.Sprintf("黑名单:%s", user)
	return redisClient.Del(ctx, lockKey).Err()
}

// 清除登录失败计数
func ClearLoginFailures(user string) error {
	failKey := fmt.Sprintf("mail:fail:%s", user)
	return redisClient.Del(ctx, failKey).Err()
}
