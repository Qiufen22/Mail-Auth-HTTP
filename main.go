package main

import (
	"fmt"
	"net/http"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger
var globalStore *UserPasswordStore

func main() {
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}

	writer := zapcore.AddSync(logFile)

	// 创建 Encoder 配置
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "ts"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encoderConfig)
	core := zapcore.NewCore(encoder, writer, zapcore.InfoLevel)

	// 创建 logger
	logger = zap.New(core, zap.AddCaller())
	defer logger.Sync()

	// 打一条启动日志
	logger.Info("程序启动", zap.String("service", "mail-auth"), zap.String("addr", ":8089"))

	// 初始化 Redis
	if err := InitRedis("10.251.65.150:6379", "123456", 0); err != nil {
		logger.Error("Redis 初始化失败", zap.Error(err))
		panic(err)
	}

	globalStore, err = NewUserPasswordStore()
	if err != nil {
		logger.Error("Mysql 初始化失败", zap.Error(err))
		panic(err)
	}

	// 初始化 TOTP 密钥
	err = globalStore.InitializeAllUsersTOTP()
	if err != nil {
		logger.Error("初始化 TOTP 时发生错误", zap.Error(err))
	}

	http.HandleFunc("/mail/auth", mailAuthHandler)
	addr := ":8089"
	logger.Info("HTTP 服务启动", zap.String("addr", addr))
	fmt.Printf("Auth HTTP 服务启动，监听 %s\n", addr)

	// 启动服务
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error("HTTP 服务错误", zap.Error(err))
		panic(err)
	}
}
