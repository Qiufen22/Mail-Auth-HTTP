package main // 修改成你自己的包名，比如 main、service 等

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // 引入 MySQL 驱动
	"go.uber.org/zap"
)

// UserPasswordStore 封装数据库操作
type UserPasswordStore struct {
	DB *sql.DB
}

// 返回：密码、是否找到、错误（系统级错误）
func (s *UserPasswordStore) GetUserPassword(username string) (password string, found bool, err error) {
	query := "SELECT password FROM users WHERE username = ?"
	var pwd string
	err = s.DB.QueryRow(query, username).Scan(&pwd)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil // 用户不存在，不是错误
		}
		return "", false, fmt.Errorf("数据库查询失败: %w", err)
	}
	return pwd, true, nil
}

// NewUserPasswordStore 初始化数据库连接并返回 store
func NewUserPasswordStore() (*UserPasswordStore, error) {
	// ✅ 请根据你的实际情况修改这里的连接信息
	dsn := "mail:123456@tcp(avl.niubi666.icu:3306)/mail?charset=utf8mb4&parseTime=true&loc=Local"

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("创建数据库连接池失败: %w", err)
	}

	// 测试连接
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("数据库连接失败: %w", err)
	}

	db.SetMaxOpenConns(600)
	db.SetMaxIdleConns(200)
	db.SetConnMaxLifetime(3 * time.Minute)

	logger.Info("数据库连接成功", zap.String("dsn", dsn))

	return &UserPasswordStore{DB: db}, nil
}
