package main

import (
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func mailAuthHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("Auth-User")
	pass := r.Header.Get("Auth-Pass")
	protocol := r.Header.Get("Auth-Protocol")
	clientIP := r.Header.Get("Client-IP")
	logger.Info("登录尝试", zap.String("账户", user), zap.String("密码", pass), zap.String("协议", protocol), zap.String("IP", clientIP))

	// 查询用户是否被锁定
	locked, _ := IsUserLocked(user)

	//查询用户的密码
	password, found, err := globalStore.GetUserPassword(user)
	if err != nil {
		logger.Error("系统错误", zap.Error(err))
		return
	}
	if !found {
		logger.Warn(fmt.Sprintf("用户 [%s] 不存在", user), zap.String("用户", user))
		return
	}

	// 如果用户被锁定
	if locked {
		logger.Warn(fmt.Sprintf("用户 [%s] 已锁定", user), zap.String("用户", user))
		// 可以添加飞书推送通知邮箱用户已锁定，登录需要添加totp码
		// .....

		// 拆分密码和totp码
		passwd := pass[:len(pass)-6]
		totpCode := pass[len(pass)-6:]

		//判断原密码中是否加入了totp码
		if GetCurrentTOTPCode(user, globalStore.DB) == totpCode {
			// 解锁
			UnlockUser(user)
			logger.Info(fmt.Sprintf("用户 [%s] 解锁成功", user), zap.String("用户", user))
			pass = passwd
		} else {
			logger.Warn(fmt.Sprintf("用户 [%s] 密码错误", user), zap.String("用户", user))
			w.Header().Set("Auth-Status", "用户已锁定，请用TOTP码登录")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		// 如果没锁定，但用户传了 password+totp，也要替换掉
		passwd := pass[:len(pass)-6]
		if pass == passwd+GetCurrentTOTPCode(user, globalStore.DB) {
			pass = passwd
		}
	}

	// 校验密码
	if pass != password {

		// 密码错误，记录失败次数
		fails, locked, err := RecordLoginFailure(user, 5, 60*time.Second, 5*time.Minute)
		if err != nil {
			logger.Error("记录登录失败次数出错", zap.Error(err))
			return
		}
		if locked {
			logger.Warn(fmt.Sprintf("用户 [%s] 锁定", user), zap.String("用户", user))
			w.Header().Set("Auth-Status", "用户已锁定，请用TOTP")
			w.WriteHeader(http.StatusForbidden)
		} else {
			logger.Warn(fmt.Sprintf("用户 [%s] 密码错误", user), zap.String("用户", user), zap.Int64("失败次数", fails))
			w.WriteHeader(http.StatusForbidden)
		}

		return
	}

	logger.Info(fmt.Sprintf("用户 [%s] 登录成功", user), zap.String("用户", user))
	// 密码正确，重置失败次数
	ClearLoginFailures(user)

	// ✅ 保证最终传给后端的一定是真实密码
	w.Header().Set("Auth-Pass", pass)

	// 后端选择
	backendServer, backendPort := selectBackend(protocol)

	w.Header().Set("Auth-Status", "OK")
	w.Header().Set("Auth-Server", backendServer)
	w.Header().Set("Auth-Port", backendPort)
	w.WriteHeader(http.StatusOK)
}
