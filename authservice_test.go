package newsystemservice

import (
	"context"
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"testing"
	//"github.com/dgrijalva/jwt-go"
	"github.com/go-pg/pg"
	//"github.com/go-pg/pg/orm"
	"github.com/sirupsen/logrus"
	//"time"
	"worklife/experimental/newsystem/remote"
)

func TestMakeTokens(t *testing.T) {
	db := pg.Connect(&pg.Options{
		User:     "postgres",
		Password: "myPassword",
		Database: "mydb",
	})

	r := repo{
		db:  db,
		log: logrus.New(),
		//Token
	}

	err := r.dropTables()
	if err != nil {
		panic(err)
	}

	err = r.createSchema()
	if err != nil {
		panic(err)
	}

	fmt.Println("created schema")

	var uid string
	uid, err = r.addUser("intarga")
	if err != nil {
		panic(err)
	}

	var users []User
	_, err = r.db.Query(&users, `SELECT * FROM users`)
	fmt.Println(users)
	fmt.Println("added user")

	ctx := context.Background()
	ctx = context.WithValue(ctx, "uid", uid)
	ctx = context.WithValue(ctx, "su", "1")
	r.token, err = r.getToken(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Println(r.token)

	var oid string
	oid, err = r.addOrg("org1")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Println("added org1")

	var pid1 string
	pid1, err = r.addProj("proj1", "org1")
	if err != nil {
		panic(err)
	}

	fmt.Println("added proj1")

	//r.giveOrgProjs("org1", "proj1")

	err = r.addRole("Owner", 0, 1, 2)
	if err != nil {
		panic(err)
	}

	fmt.Println("added Owner")

	err = r.giveUserOrgroles("intarga", "org1", "Owner")
	if err != nil {
		panic(err)
	}

	//err = r.giveUserOrgroles("intarga", "org1", "Owner")
	//if err != nil {
	//	panic(err)
	//}

	var orgroles []Orgrole
	_, err = r.db.Query(&orgroles, `SELECT * FROM orgroles`)
	fmt.Println(orgroles)

	var orgrole_roles []Orgrole_role
	_, err = r.db.Query(&orgrole_roles, `SELECT * FROM orgrole_roles`)
	fmt.Println(orgrole_roles)

	fmt.Println("Assigned orgrole")

	var pid2 string
	pid2, err = r.addProj("otherProj", "org1")
	if err != nil {
		panic(err)
	}

	err = r.addRole("Inspector", 2)
	if err != nil {
		panic(err)
	}

	r.giveUserProjroles("intarga", "otherProj", "Inspector")

	fmt.Println("added all")

	//time.Sleep(5000 * time.Millisecond)

	fmt.Println("Database:")
	fmt.Println(r.db.String())
	fmt.Println("User result")

	//ctx = context.Background()
	//ctx = context.WithValue(ctx, "uid", 1)

	err = r.updateValidator()
	var token string
	ctx = context.WithValue(ctx, "su", "0")
	token, err = r.getToken(ctx)
	if err != nil {
		panic(err)
	}

	//fmt.Println("got token")
	//fmt.Println(token)

	bmpms := make([]*roaring.Bitmap, 3)
	bmpms[2] = roaring.New()
	bmpms[2].AddMany([]uint32{0, 1, 2})
	bmpms[0] = roaring.New()
	bmpms[0].AddMany([]uint32{0, 1, 2})
	bmpms[1] = roaring.New()
	bmpms[1].AddMany([]uint32{2})
	pidms := make([]string, 3)
	pidms[0] = pid1
	pidms[2] = oid
	pidms[1] = pid2

	fmt.Println("Decrypting")
	bmparr, pidarr, _ := newsystemremote.Decrypt(token)
	fmt.Println("Decrypted")
	fmt.Println(bmparr, pidarr)
	for i := range pidms {
		if !bmparr[i].Equals(bmpms[i]) || pidarr[i] != pidms[i] {
			t.Error("no match")
		}
		fmt.Println("Expected:", bmpms[i], pidms[i])
		fmt.Println("Received:", bmparr[i], pidarr[i])
	}

	if !newsystemremote.IsAuthz(token, pid2, 2) {
		t.Error("wrong auth")
	}
	if !newsystemremote.IsAuthz(token, pid1, 0, 1, 2) {
		t.Error("wrong auth")
	}
	if !newsystemremote.IsAuthz(token, pid1, 2) {
		t.Error("wrong auth")
	}
	if newsystemremote.IsAuthz(token, pid1, 2, 3) {
		t.Error("wrong auth")
	}
	if !newsystemremote.IsAuthz(token, pid1) {
		t.Error("wrong auth")
	}
	if newsystemremote.IsAuthz(token, pid2, 0) {
		t.Error("wrong auth")
	}
	if !newsystemremote.IsAuthz(token, oid) {
		t.Error("wrong auth")
	}
	if newsystemremote.IsAuthz(token, "4") {
		t.Error("wrong auth")
	}

	r.removeRole("Inspector")
	//r.refreshAndCheck(ctx, 1, 0, 1, 2)

	r.addRole("Inspector", 3)
	err = r.giveUserProjroles("intarga", "otherProj", "Inspector")
	if err != nil {
		panic(err)
	}
	err = r.removeUserOrgroles("intarga", "org1", "Owner")
	if err != nil {
		panic(err)
	}
	r.refreshAndCheck(ctx, pid2, 3)
	r.giveUserProjroles("intarga", "otherProj", "Owner")
	r.refreshAndCheck(ctx, pid2, 0, 1, 2, 3)
	r.removeUserProjroles("intarga", "otherProj", "Inspector")
	r.refreshAndCheck(ctx, pid2, 0, 1, 2)
}

func (repo *repo) refreshAndCheck(ctx context.Context, reqid string, reqperms ...uint32) {
	err := repo.updateValidator()
	var token string
	token, err = repo.getToken(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Expected:", reqperms, reqid)
	perms, id, _ := newsystemremote.Decrypt(token)
	fmt.Println("Received:", perms, id)
}