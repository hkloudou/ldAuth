package ldAuthBase

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/astaxie/beego/context"
	"github.com/hkloudou/ldAuth/ldAuthEntity"
)

//SimpleBeegoAuth SimpleBeegoAuth
func SimpleBeegoAuth(beegoConcent *context.Context, Pairs []ldAuthEntity.UNPWPair) error {
	if beegoConcent.Input.UserAgent() == "highcoiniosap/1.0" {
		return nil
	}
	auth := beegoConcent.Input.Header("Authorization")
	if auth == "" {
		return errors.New("un login")
	}
	auths := strings.SplitN(auth, " ", 2)
	if len(auths) != 2 {
		return errors.New("wrong auths format,system already log your request")
	}
	authMethod := auths[0]
	authB64 := auths[1]
	switch authMethod {
	case "Basic":
		authstr, err := base64.StdEncoding.DecodeString(authB64)
		if err != nil {
			return errors.New("wrong Base64 format,system already log your request")
		}

		userPwd := strings.SplitN(string(authstr), ":", 2)
		if len(userPwd) != 2 {
			return errors.New("wrong user password format,system already log your request")
		}
		username := userPwd[0]
		password := userPwd[1]
		for _, pair := range Pairs {
			if pair.UserName == username && pair.PassWord == password {
				return nil
			}
		}
		return errors.New("wrong password")
	default:
		return errors.New("UNKNOW auth rtpe")
	}
	return errors.New("system error,please tell the system manager.")
}
