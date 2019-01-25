package newsystemremote

import (
	//"errors"
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"github.com/dgrijalva/jwt-go"
	//"strconv"
)

const (
	Secretkey  = "mySuperSecretKeyLol"
	ForestRock = 0
	prf        = 0
)

// Currently no encryption!!!
func Decrypt(tokenString string) ([]*roaring.Bitmap, []string, string) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(Secretkey), nil
	})

	//fmt.Println("about to read claims")
	//fmt.Println(tokenString)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		fmt.Println(err)
		fmt.Println(token.Valid)
	}
	//fmt.Println("extracted claims")
	bmpifc := claims["bmps"].([]interface{})
	pidifc := claims["pids"].([]interface{})
	//fmt.Println(bmpifc, ", ", pidifc)
	//fmt.Println("as arrays")
	bmparr := make([]*roaring.Bitmap, len(bmpifc))
	pidarr := make([]string, len(pidifc))
	//fmt.Println("constructed return arrays")
	for i := range bmpifc {
		//fmt.Println(bmpifc[i])
		bmpbyte := []byte(bmpifc[i].(string))
		//fmt.Println("[]byte unpacked")
		bmparr[i] = roaring.New()
		err := bmparr[i].UnmarshalBinary(bmpbyte)
		//fmt.Println("unmarshaled")
		if err != nil {
			panic(err)
		}
		//var inthold int64
		//inthold, err = strconv.ParseInt(pidifc[i].(string), 10, 0)
		if err != nil {
			panic(err)
		}
		pidarr[i] = pidifc[i].(string)
	}
	return bmparr, pidarr, claims["su"].(string)
}

func IsAuthz(tokenString string, reqid string, reqperms ...uint32) bool {
	req := roaring.New()
	for _, v := range reqperms {
		req.Add(v)
	}

	dataarr, pidarr, su := Decrypt(tokenString)

	if su == "1" {
		return true
	}

	fmt.Println(reqid, pidarr)
	for i, data := range dataarr {
		pid := pidarr[i]
		if pid == reqid && (roaring.And(data, req)).Equals(req) {
			return true
		}
	}
	return false
}