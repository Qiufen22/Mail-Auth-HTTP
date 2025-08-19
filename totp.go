package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// 全局配置
var TOTPSecretLength = 16
var TOTPIssuer = "mail-auth" // 替换为你的应用名

// ValidateCurrentTOTP 校验用户输入的 TOTP 口令是否正确
// username: 用户名
// inputCode: 用户输入的 6 位数字（字符串）
// db: 数据库连接
// 返回: true 表示验证通过
func ValidateCurrentTOTP(username, inputCode string, db *sql.DB) bool {
	var secret string
	err := db.QueryRow("SELECT totp_secret FROM users WHERE username = ? AND totp_enabled = 1", username).
		Scan(&secret)
	if err != nil {
		log.Printf("查询 TOTP 密钥失败: %v", err)
		logger.Error("查询 TOTP 密钥失败", zap.String("username", username), zap.Error(err))
		return false
	}

	if secret == "" {
		log.Printf("用户 %s 的 TOTP 密钥为空", username)
		logger.Warn(fmt.Sprintf("用户 [%s] 的 TOTP 密钥为空", username), zap.String("username", username))
		return false
	}

	// 使用 totp 包验证
	valid := totp.Validate(inputCode, secret)
	return valid
}

// 程序启动时调用，为所有用户生成 TOTP 密钥
func (store *UserPasswordStore) InitializeAllUsersTOTP() error {
	// 查询所有用户（且未初始化 TOTP 的也重新初始化）
	rows, err := store.DB.Query("SELECT username FROM users")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			logger.Error("读取用户名失败", zap.Error(err))
			continue
		}

		// 查询当前用户是否已启用 TOTP
		var secret string
		var enabled int
		err := store.DB.QueryRow("SELECT totp_secret, totp_enabled FROM users WHERE username = ?", username).Scan(&secret, &enabled)
		if err != nil {
			logger.Error("查询用户 TOTP 状态失败", zap.String("username", username), zap.Error(err))
			continue
		}

		if secret != "" && enabled == 1 {
			// 已有密钥且已启用，跳过
			logger.Info("用户已存在 TOTP 密钥，跳过", zap.String("username", username))
			continue
		}

		// 生成 TOTP 密钥
		secret, err = generateTOTPSecret(username)
		if err != nil {
			logger.Error("生成 TOTP 失败", zap.String("username", username), zap.Error(err))
			continue
		}

		// 写入数据库（如果已有则更新）
		_, err = store.DB.Exec(
			"UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE username = ?",
			secret, username,
		)
		if err != nil {
			logger.Error("保存 TOTP 到数据库失败", zap.String("username", username), zap.Error(err))
			continue
		}

		logger.Info("已为用户生成 TOTP 密钥", zap.String("username", username))
	}

	return nil
}

// 生成一个标准的 TOTP Base32 密钥
func generateTOTPSecret(username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("用户名不能为空")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: username,
		Period:      30,
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// GetCurrentTOTPCode 根据用户名，返回当前 TOTP 六位口令
// 如果失败（用户不存在、secret 为空等），返回空字符串
func GetCurrentTOTPCode(username string, db *sql.DB) string {
	var secret string

	// 从数据库查询 totp_secret
	err := db.QueryRow("SELECT totp_secret FROM users WHERE username = ?", username).
		Scan(&secret)

	if err != nil || secret == "" {
		log.Printf("用户 %s 未找到或 TOTP 密钥为空", username)
		return ""
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		log.Printf("生成 TOTP 失败 %s: %v", username, err)
		return ""
	}

	return code // 返回 6 位字符串，如 "123456"
}
