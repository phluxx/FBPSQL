package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Mysql MysqlConfig
	Jwt   JwtConfig
	Http  HttpConfig
	Ldap  LdapConfig
}

type LdapConfig struct {
	Host     string `envconfig:"LDAP_HOST"`
	BaseDN   string `envconfig:"LDAP_BASE_DN"`
	Username string `envconfig:"LDAP_USERNAME"`
	Password string `envconfig:"LDAP_PASSWORD"`
}

type HttpConfig struct {
	Port  string `envconfig:"HTTP_PORT"`
	Proto string `envconfig:"HTTP_PROTO" default:"https"`
	Host  string `envconfig:"HTTP_HOST"`
}

type JwtConfig struct {
	Secret string `envconfig:"JWT_SECRET"`
}

type MysqlConfig struct {
	User   string `envconfig:"MYSQL_USER"`
	Passwd string `envconfig:"MYSQL_PASSWORD"`
	Host   string `envconfig:"MYSQL_HOST"`
	DBName string `envconfig:"MYSQL_DATABASE"`
}

func New() (*Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
