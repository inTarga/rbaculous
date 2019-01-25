package newsystemservice

import (
	"errors"
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-pg/pg"
	//"github.com/go-pg/pg/orm"
	"context"
	"github.com/sirupsen/logrus"
	remote "worklife/experimental/newsystem/remote"
	"worklife/utils"
)

const (
	Secretkey = "mySuperSecretKeyLol"
)

/*
type PermRepo interface { //update...
	getAllProjroles(uid int) ([]Projrole, error)
	evaluateOrgrole(orgrole Orgrole) ([]Projrole, error)
	evaluateProjrole(projrole Projrole) ([]string, int, error)
	getPerms(rolename string) ([]uint32, error)
	genMap(roles []string) (*roaring.Bitmap, error)
	makeToken(bmp *roaring.Bitmap, pid int) (string, error)
	getTokens(ctx context.Context) ([]string, error)
	createSchema() error
	addUser(user User) error
	addOrg(org Org) error
	addProj(proj Proj) error
	addRole(role Role) error
}
*/

//----Models----//for extracting rows from the pg database.

type User struct {
	Id        string // `sql:",pk"`
	Name      string
	Token     string
	Validator string
}

//
type Orgrole struct {
	Id   string
	User string
	Org  string
}

//
type Projrole struct {
	Id   string
	User string
	Proj string
}

//
type Grprole struct {
	Id   string
	User string
	Grp  string
}

type Orgrole_role struct {
	Orgrole string
	Role    string
}

type Projrole_role struct {
	Projrole string
	Role     string
}

type Grprole_role struct {
	Grprole string
	Role    string
}

type Org struct {
	Id   string
	Name string // `sql:",pk"`
}

type Proj struct {
	Id   string
	Name string // `sql:",pk"`
	Org  string
}

type Grp struct {
	Id   string
	Name string // `sql:",pk"`
	Org  string
}

type Grp_grp struct {
	Parent_grp string
	Child_grp  string
}

type Grp_proj struct {
	Grp  string
	Proj string
}

type Role struct {
	Name  string   // `sql:",pk"`
	Perms []uint32 `pg:",array"`
}

//----Repo----

// Collects the db,log,and a user token into a struct for methods to act on.
type repo struct {
	db    *pg.DB
	log   *logrus.Logger
	token string
}

//----Token Generation----

// Inserts a bitmap into a map at a given string if there isnt one there. If there is one,
// it computes the and of them, and puts that instead.
func mergeInsert(datmap map[string]*roaring.Bitmap, key string, inval *roaring.Bitmap) {
	//fmt.Println("inserting", inval)
	val, ok := datmap[key]
	if !ok {
		datmap[key] = inval
	} else {
		datmap[key] = roaring.And(val, inval)
	}
}

// for a specified role, gets an slice of its permissions from the db.
func (repo *repo) getPerms(rolename string) ([]uint32, error) {
	var role Role //read role from db into var
	_, err := repo.db.QueryOne(&role, `SELECT * FROM roles WHERE name = ?`, rolename)
	if err != nil {
		repo.log.Debug(err)
	}

	return role.Perms, err
}

//Creates a permissions bitmap from a slice of roles.
func (repo *repo) genMap(roles []string) (*roaring.Bitmap, error) {
	s := roaring.New() //create bitmap
	var err error
	for _, role := range roles {
		var perms []uint32 //read role's perms from db into var
		perms, err = repo.getPerms(role)
		s.AddMany(perms) //add these to bitmap
	}

	return s, err
}

// For a user, gets all their orgroles from the db, processes them into projroles and a nub,
// then makes bitmaps of them and mergeInserts them into a map.
func (repo *repo) evaluateOrgroles(uid string, datmap map[string]*roaring.Bitmap) (map[string]*roaring.Bitmap, error) {
	var orgroles []Orgrole
	_, err := repo.db.Query(&orgroles,
		`SELECT id, org FROM orgroles WHERE "user" = ?`, uid)
	if err != nil {
		repo.log.Debug(err)
		return datmap, err
	}

	fmt.Println("orgroles evaluating:", orgroles)

	for _, orgrole := range orgroles {
		var roles []string
		_, err = repo.db.Query(&roles, //pg.Scan(&roles),
			`SELECT role FROM orgrole_roles	WHERE orgrole = ?`, orgrole.Id)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}
		var bmp *roaring.Bitmap
		bmp, err = repo.genMap(roles)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}

		var projs []string
		_, err = repo.db.Query(&projs, //pg.Scan(&projs),
			`SELECT id FROM projs WHERE org = ?`, orgrole.Org)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}

		for _, proj := range projs {
			mergeInsert(datmap, proj, bmp)
		}
		mergeInsert(datmap, orgrole.Org, bmp) //adds nub for org level perms
	}

	return datmap, err
}

// For a given group, gets all its projects, and the projects of its subgroups recursively.
// you'll generally want to make an empty map to pass into this.
func (repo *repo) getGrpProjs(projmap map[string]bool, grp string) (map[string]bool, error) {
	var projs []string
	_, err := repo.db.Query(&projs,
		`SELECT proj FROM grp_projs WHERE grp = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		return projmap, err
	}

	for _, proj := range projs {
		projmap[proj] = true
	}

	var grps []string
	_, err = repo.db.Query(&grps,
		`SELECT child_grp FROM grp_grps WHERE parent_grp = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		return projmap, err
	}

	for _, subgrp := range grps {
		projmap, err = repo.getGrpProjs(projmap, subgrp)
	}

	return projmap, err
}

// For a user, gets all their grproles from the db, processes them into projroles,
// then makes bitmaps of them and mergeInserts them into a map.
func (repo *repo) evaluateGrproles(uid string, datmap map[string]*roaring.Bitmap) (map[string]*roaring.Bitmap, error) {
	var grproles []Grprole
	_, err := repo.db.Query(&grproles,
		`SELECT * FROM grproles WHERE "user" = ?`, uid)
	if err != nil {
		repo.log.Debug(err)
		return datmap, err
	}

	for _, grprole := range grproles {
		var roles []string
		_, err = repo.db.Query(&roles,
			`SELECT role FROM grprole_roles WHERE grprole = ?`, grprole.Id)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}
		var bmp *roaring.Bitmap
		bmp, err = repo.genMap(roles)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}

		projmap := make(map[string]bool)
		repo.getGrpProjs(projmap, grprole.Grp)

		for proj := range projmap {
			mergeInsert(datmap, proj, bmp)
		}
	}

	return datmap, err
}

// For a user, gets all their projroles from the db,
// then makes bitmaps of them and mergeInserts them into a map.
func (repo *repo) evaluateProjroles(uid string, datmap map[string]*roaring.Bitmap) (map[string]*roaring.Bitmap, error) {
	var projroles []Projrole
	_, err := repo.db.Query(&projroles,
		`SELECT * FROM projroles WHERE "user" = ?`, uid)
	if err != nil {
		repo.log.Debug(err)
		return datmap, err
	}

	for _, projrole := range projroles {
		var roles []string
		_, err = repo.db.Query(&roles,
			`SELECT role FROM projrole_roles WHERE projrole = ?`, projrole.Id)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}
		var bmp *roaring.Bitmap
		bmp, err = repo.genMap(roles)
		if err != nil {
			repo.log.Debug(err)
			return datmap, err
		}

		mergeInsert(datmap, projrole.Proj, bmp)
	}

	return datmap, err
}

// Takes a map of strings to bitmaps, and returns slices of keys and values matched by index.
func toStringArrs(datmap map[string]*roaring.Bitmap) ([]string, []string, error) {
	bmparr := make([]string, 0, len(datmap))
	idarr := make([]string, 0, len(datmap))
	var err error

	for id, bmp := range datmap {
		bmpbyte, err := bmp.MarshalBinary()
		if err != nil {
			return bmparr, idarr, err
		}

		bmparr = append(bmparr, string(bmpbyte))
		idarr = append(idarr, id)
	}

	return bmparr, idarr, err
}

// Takes an array of bitmaps, its corresponding array of proj/org ids, and a superuser permission,
// and generates a jwt holding them.
func (repo *repo) makeToken(bmparr []string, idarr []string, su string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"bmps": bmparr,
		"pids": idarr,
		"su":   su,
	})

	return token.SignedString([]byte(Secretkey)) //includes error
}

// For user data passed in through context (user id, su status) returns a token for them.
// It returns a cached token if they have a valid one, else it gets their data from the
// db and generates a new one.
func (repo *repo) getToken(ctx context.Context) (string, error) {
	uid := ctx.Value("uid").(string)

	//put auth0 hook here

	token, ok, err := repo.getCached(uid)
	if err != nil && err != pg.ErrNoRows {
		//panic(err)
		return "", err
	}
	if ok {
		return token, err
	}

	var datmap map[string]*roaring.Bitmap
	datmap, err = repo.evaluateOrgroles(uid, make(map[string]*roaring.Bitmap))
	if err != nil {
		//panic(err)
		return "", err
	}

	datmap, err = repo.evaluateGrproles(uid, datmap)
	if err != nil {
		return "", err
	}

	datmap, err = repo.evaluateProjroles(uid, datmap)
	if err != nil {
		return "", err
	}

	var bmparr []string
	var idarr []string
	bmparr, idarr, err = toStringArrs(datmap)
	if err != nil {
		panic(err)
		return "", err
	}

	//fmt.Println("into token", bmparr, idarr, datmap)

	token, err = repo.makeToken(bmparr, idarr, ctx.Value("su").(string))
	if err != nil {
		return token, err
	}

	err = repo.putCache(uid, token)
	if err != nil {
		panic(err)
	}

	return token, err
}

// Checks the token cache for a user, if there's a valid token there it returns it with ok=true,
// else returns empty string with ok=false.
func (repo *repo) getCached(uid string) (string, bool, error) {
	var user User
	_, err := repo.db.QueryOne(&user, `SELECT token, validator FROM users WHERE id = ?`, uid)
	if user.Token == "" {
		return user.Token, false, err
	}

	var validator string
	_, err = repo.db.QueryOne(&validator, `SELECT validator FROM token_validator`)
	if validator != user.Validator {
		return "", false, err
	}

	return user.Token, true, err
}

// Puts a token in the token cache.
func (repo *repo) putCache(uid string, token string) error {
	var validator string
	_, err := repo.db.QueryOne(&validator, `SELECT validator FROM token_validator`)
	if err != nil {
		return err
	}
	_, err = repo.db.Exec(
		`UPDATE users SET token = ?0, validator = ?1 WHERE id = ?2`, token, validator, uid)
	return err
}

// Updates the token validator, making all current tokens invalid.
// Users will then have to generate a new token.
func (repo *repo) updateValidator() error {
	_, err := repo.db.Exec(`UPDATE token_validator SET validator = ?`, utils.NewId())
	return err
}

//----Database Construction----

// Clears the db of tables by dropping the public schema then reinstating it.
func (repo *repo) dropTables() error {
	_, err := repo.db.Exec(`
	DROP SCHEMA public CASCADE;
	CREATE SCHEMA public;`)
	return err
}

//Sets up the database with the relevant tables.
func (repo *repo) createSchema() error {
	_, err := repo.db.Exec(`CREATE TABLE users
	(
		id			text PRIMARY KEY,
		name		text UNIQUE,
		token		text,
		validator	text
	);

	CREATE TABLE orgs
	(
		id			text PRIMARY KEY,
		name		text UNIQUE
	);

	CREATE TABLE grps
	(
		id			text PRIMARY KEY,
		name		text UNIQUE,
		org			text REFERENCES orgs		ON DELETE CASCADE
	);

	CREATE TABLE projs
	(
		id			text PRIMARY KEY,
		name		text UNIQUE,
		org			text REFERENCES orgs		ON DELETE CASCADE
	);

	CREATE TABLE grp_grps --junction
	(
		parent_grp	text REFERENCES grps		ON DELETE CASCADE,
		child_grp	text REFERENCES grps		ON DELETE CASCADE
	);

	CREATE TABLE grp_projs --junction
	(
		grp			text REFERENCES grps		ON DELETE CASCADE,
		proj		text REFERENCES projs		ON DELETE CASCADE
	);

	CREATE TABLE roles
	(
		name		text PRIMARY KEY,
		perms		integer[]
	);

	CREATE TABLE orgroles
	(
		id			text PRIMARY KEY,
		"user"		text REFERENCES	users		ON DELETE CASCADE,
		org			text REFERENCES	orgs		ON DELETE CASCADE
	);

	CREATE TABLE grproles
	(
		id			text PRIMARY KEY,
		"user"		text REFERENCES	users		ON DELETE CASCADE,
		grp			text REFERENCES	grps		ON DELETE CASCADE
	);

	CREATE TABLE projroles
	(
		id			text PRIMARY KEY,
		"user"		text REFERENCES	users		ON DELETE CASCADE,
		proj		text REFERENCES	projs		ON DELETE CASCADE
	);

	CREATE TABLE orgrole_roles --junction
	(
		orgrole		text REFERENCES orgroles	ON DELETE CASCADE,
		role		text REFERENCES	roles		ON DELETE CASCADE
	);

	CREATE TABLE grprole_roles --junction
	(
		grprole		text REFERENCES grproles	ON DELETE CASCADE,
		role		text REFERENCES	roles		ON DELETE CASCADE
	);

	CREATE TABLE projrole_roles --junction
	(
		projrole	text REFERENCES projroles	ON DELETE CASCADE,
		role		text REFERENCES	roles		ON DELETE CASCADE
	);
	
	CREATE TABLE token_validator
	(
		validator	text
	);`)

	if err != nil {
		repo.log.Debug(err) //fmt.Println("schema error", err)
		return err
	}

	_, err = repo.db.Exec(`INSERT INTO token_validator (validator) VALUES (?)`, utils.NewId())
	if err != nil {
		repo.log.Debug(err)
	}
	return err
}

// Creates a new user with the specified username, and returns the new ID assigned to them.
func (repo *repo) addUser(username string) (string, error) { //permission level?
	id := utils.NewId()

	user := &User{Id: id, Name: username}
	err := repo.db.Insert(user)
	if err != nil {
		repo.log.Debug(err)
	}

	return id, err
}

// Creates a new organisation with the specified name, returns the new ID assigned to it.
func (repo *repo) addOrg(orgname string) (string, error) { //superuser only?
	id := utils.NewId()

	org := &Org{Id: id, Name: orgname}
	err := repo.db.Insert(org)
	if err != nil {
		repo.log.Debug(err)
	}

	return id, err
}

// Creates a new project with the specified name belonging to the specified organisation,
// returns the new ID assigned to it.
func (repo *repo) addProj(projname string, orgname string) (string, error) { //automate projID assignment?
	id := utils.NewId()
	var orgid string
	var err error
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, orgname)
	if err != nil {
		panic(err)
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return "", err
	}

	proj := &Proj{Id: id, Name: projname, Org: orgid}
	err = repo.db.Insert(proj)
	if err != nil {
		repo.log.Debug(err)
	}

	return id, err
}

// Creates a new group with the specified name belonging to the specified organisation,
// returns the new ID assigned to it.
func (repo *repo) addGrp(grpname string, orgname string) error {
	id := utils.NewId()
	var orgid string
	var err error
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, orgname)
	if err != nil {
		panic(err)
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	grp := &Grp{Id: id, Name: grpname, Org: orgid}
	err = repo.db.Insert(grp)
	if err != nil {
		repo.log.Debug(err)
	}

	return err
}

// Creates a new role with the specified name and permissions.
func (repo *repo) addRole(rolename string, perms ...uint32) error { //permission level?
	role := &Role{Name: rolename, Perms: perms}

	err := repo.db.Insert(role)
	if err != nil {
		repo.log.Debug(err)
	}

	return err
}

//----Database Editing----

// Returns the bitmap of permissions a specified user has in a specified project.
func (repo *repo) getUserProjBitmap(uid string, pid string) (*roaring.Bitmap, error) {
	datmap, err := repo.evaluateOrgroles(uid, make(map[string]*roaring.Bitmap))
	datmap, err = repo.evaluateGrproles(uid, datmap)
	datmap, err = repo.evaluateProjroles(uid, datmap)
	val, ok := datmap[pid]
	if !ok {
		return roaring.New(), err
	}
	return val, err
}

// Returns a bool of whether a given user is in the database by id.
func (repo *repo) checkExistsUser(username string) (bool, error) {
	var user User
	_, err := repo.db.QueryOne(&user, `SELECT * FROM users WHERE name = ?`, username)
	return err == nil, err
}

// Returns a bool of whether a given organisation is in the database by name.
func (repo *repo) checkExistsOrg(orgname string) (bool, error) {
	var org Org
	_, err := repo.db.QueryOne(&org, `SELECT * FROM orgs WHERE name = ?`, orgname)
	return err == nil, err
}

// Returns a bool of whether a given project is in the database by name.
func (repo *repo) checkExistsProj(projname string) (bool, error) {
	var proj Proj
	_, err := repo.db.QueryOne(&proj, `SELECT * FROM projs WHERE name = ?`, projname)
	return err == nil, err
}

// Returns a bool of whether a given group is in the database by name.
func (repo *repo) checkExistsGrp(grpname string) (bool, error) {
	var grp Grp
	_, err := repo.db.QueryOne(&grp, `SELECT * FROM grps WHERE name = ?`, grpname)
	return err == nil, err
}

// Returns a bool of whether a given role is in the database by name.
func (repo *repo) checkExistsRole(rolename string) (bool, error) {
	var role Role
	_, err := repo.db.QueryOne(&role, `SELECT * FROM roles WHERE name = ?`, rolename)
	return err == nil, err
}

// Assigns roles to a user at the organisation level.
func (repo *repo) giveUserOrgroles(username string, org string, roles ...string) error { //testbothcases
	var err error
	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, org)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist")
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var orgrole Orgrole
	_, err = repo.db.QueryOne(&orgrole, `SELECT * FROM orgroles WHERE "user" = ?0 AND org = ?1`, uid, orgid)
	orgroleid := orgrole.Id
	//fmt.Println(orgrole, err)
	if err == pg.ErrNoRows {
		//fmt.Println("detected:", err)
		orgroleid = utils.NewId()
		//orgrole := &Orgrole{Id: orgroleid, Org: orgid, User: uid}
		//fmt.Println("orgrole:", orgrole)
		_, err = repo.db.Exec(`INSERT INTO orgroles	VALUES (?0, ?1, ?2)`, orgroleid, uid, orgid)
		//err = repo.db.Insert(orgrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	for _, inrole := range roles {
		var orgrole_role Orgrole_role
		_, err = repo.db.QueryOne(&orgrole_role,
			`SELECT * FROM orgrole_roles WHERE orgrole = ?0 AND role = ?1`, orgroleid, inrole) //can be made more efficient, ignore in case of new orgrole
		//fmt.Println(orgrole_role, inrole, err)
		if err == pg.ErrNoRows {
			orgrole_role := &Orgrole_role{Orgrole: orgroleid, Role: inrole}
			err = repo.db.Insert(orgrole_role)
			//fmt.Println("Inserted", err, orgrole_role)
			if err != nil {
				repo.log.Debug(err)
				return err
			}
		}
	}

	return err
}

// Assigns roles to a user at the project level.
func (repo *repo) giveUserProjroles(username string, proj string, roles ...string) error {
	var err error
	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var projid string
	_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Proj does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist")
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var projrole Projrole
	_, err = repo.db.QueryOne(&projrole, `SELECT * FROM projroles WHERE "user" = ?0 AND proj = ?1`, uid, projid)
	projroleid := projrole.Id
	if err == pg.ErrNoRows {
		projroleid = utils.NewId()
		projrole = Projrole{Id: projroleid, Proj: projid, User: uid}
		err = repo.db.Insert(&projrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	for _, inrole := range roles {
		var projrole_role Projrole_role
		_, err = repo.db.QueryOne(&projrole_role,
			`SELECT * FROM projrole_roles WHERE projrole = ?0 AND role = ?1`, projroleid, inrole) //can be made more efficient, ignore in case of new orgrole

		if err == pg.ErrNoRows {
			projrole_role := Projrole_role{Projrole: projroleid, Role: inrole}
			err = repo.db.Insert(&projrole_role)
			if err != nil {
				repo.log.Debug(err)
				return err
			}
		}
	}

	return err
}

// Assigns a user roles at the project level for a group of projects/groups.
func (repo *repo) giveUserGrproles(username string, grp string, roles ...string) error {
	var err error
	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist")
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var grprole Grprole
	_, err = repo.db.QueryOne(&grprole, `SELECT * FROM grproles WHERE "user" = ?0 AND grp = ?1`, uid, grpid)
	grproleid := grprole.Id
	if err == pg.ErrNoRows {
		grproleid = utils.NewId()
		grprole = Grprole{Id: grproleid, Grp: grpid, User: uid}
		err = repo.db.Insert(&grprole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	for _, inrole := range roles {
		var role Role
		_, err = repo.db.QueryOne(&role,
			`SELECT * FROM grprole_roles WHERE grprole = ?0 AND role = ?1`, grproleid, inrole) //can be made more efficient, ignore in case of new orgrole
		if err == pg.ErrNoRows {
			grprole_role := Grprole_role{Grprole: grproleid, Role: inrole}
			err = repo.db.Insert(&grprole_role)
			if err != nil {
				repo.log.Debug(err)
				return err
			}
		}
	}

	return err
}

// Strips a user of organisation level roles
func (repo *repo) removeUserOrgroles(username string, org string, roles ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, org)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist")
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var orgrole string
	_, err = repo.db.QueryOne(&orgrole, `SELECT id FROM orgroles WHERE org = ?0 AND "user" = ?1`, orgid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	for _, outrole := range roles {
		fmt.Println("deleting:", orgrole, outrole)
		_, err = repo.db.Exec(`DELETE FROM orgrole_roles WHERE orgrole = ?0 AND role = ?1`, orgrole, outrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
		fmt.Println("deleted")
	}

	var count int
	_, err = repo.db.Query(&count, `SELECT COUNT(*) FROM orgrole_roles WHERE orgrole = ?`, orgrole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}
	fmt.Println("counted:", count)

	if count == 0 {
		_, err = repo.db.Exec(`DELETE FROM orgroles WHERE id = ?`, orgrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Strips a user of all their organisation level roles within an organisation.
func (repo *repo) removeUserOrgroleFull(username string, org string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, org)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist")
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var orgrole string
	_, err = repo.db.QueryOne(&orgrole, `SELECT id FROM orgroles WHERE org = ?0 AND "user" = ?1`, orgid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM orgroles WHERE id = ?`, orgrole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Strips a user of project level roles
func (repo *repo) removeUserProjroles(username string, proj string, roles ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var projid string
	_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Proj does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var projrole string
	_, err = repo.db.QueryOne(&projrole, `SELECT id FROM projroles WHERE proj = ?0 AND "user" = ?1`, projid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	for _, outrole := range roles {
		_, err = repo.db.Exec(`DELETE FROM projrole_roles WHERE projrole = ?0 AND role = ?1`, projrole, outrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	var count int
	_, err = repo.db.Query(&count, `SELECT COUNT(*) FROM projrole_roles WHERE projrole = ?`, projrole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	if count == 0 {
		_, err = repo.db.Exec(`DELETE FROM projroles WHERE id = ?`, projrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Strips a user of all roles within a project.
func (repo *repo) removeUserProjroleFull(username string, proj string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var projid string
	_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Proj does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM projs WHERE name = ?`, proj)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var projrole string
	_, err = repo.db.QueryOne(&projrole, `SELECT id FROM projroles WHERE proj = ?0 AND "user" = ?1`, projid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM projroles WHERE id = ?`, projrole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Strips a user of roles assigned through a project group.
func (repo *repo) removeUserGrproles(username string, grp string, roles ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var grprole string
	_, err = repo.db.QueryOne(&grprole, `SELECT id FROM grproles WHERE grp = ?0 AND "user" = ?1`, grpid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	for _, outrole := range roles {
		_, err = repo.db.Exec(`DELETE FROM grprole_roles WHERE grprole = ?0 AND role = ?1`, grprole, outrole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	var count int
	_, err = repo.db.Query(&count, `SELECT COUNT(*) FROM grprole_roles WHERE grprole = ?`, grprole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	if count == 0 {
		_, err = repo.db.Exec(`DELETE FROM grproles WHERE id = ?`, grprole)
		if err != nil {
			repo.log.Debug(err)
			return err
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Strips a user of all roles assigned through a project group.
func (repo *repo) removeUserGrproleFull(username string, grp string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var uid string
	_, err = repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("User does not exist")
		repo.log.Debug(err)
		return err
	}

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grp)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	var grprole string
	_, err = repo.db.QueryOne(&grprole, `SELECT id FROM grproles WHERE grp = ?0 AND "user" = ?1`, grpid, uid)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM grproles WHERE id = ?`, grprole)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Assigns project subgroups to a project group.
func (repo *repo) giveGrpGrps(grpname string, subgrps ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	for _, subgrp := range subgrps { //loop through subgrps to add
		var subgrpid string
		_, err = repo.db.QueryOne(&subgrpid, `SELECT id FROM grps WHERE name = ?`, subgrp)
		if err != nil {
			repo.log.Debug(err)
			err = errors.New("Subgrp does not exist")
			repo.log.Debug(err)
			return err
		}
		var grp_grp Grp_grp
		_, err = repo.db.QueryOne(&grp_grp,
			`SELECT * FROM grp_grps WHERE parent_grp = ?0 AND child_grp = ?1`, grpid, subgrpid)
		if err != nil {
			grp_grp = Grp_grp{Parent_grp: grpid, Child_grp: subgrpid}
			err = repo.db.Insert(grp_grp)
			if err != nil {
				return err
			}
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Removes project subgroups from a project group.
func (repo *repo) removeGrpGrps(grpname string, subgrps ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	for _, outsubgrp := range subgrps { //loop through subgrps to delete
		var subgrpid string
		_, err = repo.db.QueryOne(&subgrpid, `SELECT id FROM grps WHERE name = ?`, outsubgrp)
		if err != nil {
			repo.log.Debug(err)
			err = errors.New("Subgrp does not exist")
			repo.log.Debug(err)
			return err
		}
		_, err = repo.db.Exec(`DELETE FROM grp_grps WHERE parent_grp = ?0 AND child_grp = ?1`, grpid, subgrpid)
		if err != nil {
			return err
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Assigns projects to a project group.
func (repo *repo) giveGrpProjs(grpname string, projs ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	for _, proj := range projs { //loop through subgrps to add
		var projid string
		_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, proj)
		if err != nil {
			repo.log.Debug(err)
			err = errors.New("Proj does not exist")
			repo.log.Debug(err)
			return err
		}
		var grp_proj Grp_proj
		_, err = repo.db.QueryOne(&grp_proj,
			`SELECT * FROM grp_projs WHERE grp = ?0 AND proj = ?1`, grpid, projid)
		if err != nil {
			grp_proj = Grp_proj{Grp: grpid, Proj: projid}
			err = repo.db.Insert(grp_proj)
			if err != nil {
				return err
			}
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Removes projects from a project group.
func (repo *repo) removeGrpProjs(grpname string, projs ...string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var grpid string
	_, err = repo.db.QueryOne(&grpid, `SELECT id FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Grp does not exist")
		repo.log.Debug(err)
		return err
	}

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	for _, outproj := range projs { //loop through subgrps to delete
		var projid string
		_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, outproj)
		if err != nil {
			repo.log.Debug(err)
			err = errors.New("Proj does not exist")
			repo.log.Debug(err)
			return err
		}
		_, err = repo.db.Exec(`DELETE FROM grp_projs WHERE grp AND proj = ?1`, grpid, projid)
		if err != nil {
			return err
		}
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Assigns permissions to a role.
func (repo *repo) giveRolePerms(rolename string, perms ...uint32) error { //permission level?
	role := &Role{Name: rolename}
	err := repo.db.Select(role)
	if err != nil {
		return err
	}

	for _, inperm := range perms { //loop through perms to add
		found := false
		for _, perm := range role.Perms { //loop through role's perms
			if perm == inperm { //if found
				found = true //mark
				break
			}
		}
		if !found { //if not found
			role.Perms = append(role.Perms, inperm) //add
		}
	}

	err = repo.db.Update(role)
	if err != nil {
		repo.log.Debug(err)
	}

	return err
}

// Removes permissions from a role.
func (repo *repo) removeRolePerms(rolename string, perms ...uint32) error { //permission level?
	role := &Role{Name: rolename}
	err := repo.db.Select(role)
	if err != nil {
		return err
	}

	remarr := make([]int, 0, len(perms))
	for _, outperm := range perms { //loop through perms to delete
		for i, perm := range role.Perms { //loop through role's perms
			if perm == outperm { //if found
				remarr = append(remarr, i) //mark
				break
			}
		}
	}
	for i, j := range remarr { //remove marked perms
		role.Perms[j] = role.Perms[len(role.Perms)-i-1]
	}
	role.Perms = role.Perms[:len(role.Perms)-len(remarr)]

	err = repo.db.Update(role)
	if err != nil {
		repo.log.Debug(err)
	}

	return err
}

//----Delete Rows----

// Removes a user from the database.
func (repo *repo) removeUser(uid string) error { //permission level?
	_, err := repo.db.Exec(`DELETE FROM users WHERE id = ?`, uid)
	if err != nil {
		repo.log.Debug(err)
	}
	return err
}

// Removes an organisation and users' associated organisation level roles from the database.
func (repo *repo) removeOrg(orgname string) error { //permission level?
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, orgname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM orgs where name = ?`, orgname) //delete from db
	if err != nil {
		repo.log.Debug(err)
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err
}

// Removes a project and all its links from the database.
func (repo *repo) removeProj(projname string) error {
	_, err := repo.db.Exec(`BEGIN`)
	//tx, err := repo.db.Begin()
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)
	//defer tx.Rollback()

	var projid string
	_, err = repo.db.QueryOne(&projid, `SELECT id FROM projs WHERE name = ?`, projname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, projid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM projs where name = ?`, projname)
	if err != nil {
		repo.log.Debug(err)
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err //tx.Commit()
}

// Removes a project group and all its links from the database.
func (repo *repo) removeGrp(grpname string) error {
	_, err := repo.db.Exec(`BEGIN`)
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	var orgid string
	_, err = repo.db.QueryOne(&orgid, `SELECT org FROM grps WHERE name = ?`, grpname)
	if err != nil {
		repo.log.Debug(err)
		err = errors.New("Org does not exist") //?
		repo.log.Debug(err)
		return err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return err
	}

	_, err = repo.db.Exec(`DELETE FROM grps where name = ?`, grpname) //delete from db
	if err != nil {
		repo.log.Debug(err)
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err //tx.Commit()
}

// Removes a role and all its links from the database.
func (repo *repo) removeRole(rolename string) error { //permission level?
	_, err := repo.db.Exec(`BEGIN`)
	//tx, err := repo.db.Begin()
	if err != nil {
		repo.log.Debug(err)
		return err
	}

	defer repo.db.Exec(`ROLLBACK`)

	_, err = repo.db.Exec(`DELETE FROM roles where name = ?`, rolename) //delete from db
	if err != nil {
		repo.log.Debug(err)
	}

	_, err = repo.db.Exec(`COMMIT`)
	return err //tx.Commit()
}

// A faster way of deleting a role that does not actually delete it, but just removes it permissions.
func (repo *repo) removeRoleSoft(rolename string) error { //permission level?
	role := &Role{ //create dud role
		Name:  rolename,
		Perms: []uint32{},
	}

	err := repo.db.Update(role) //update role in db with dud
	if err != nil {
		repo.log.Debug(err)
	}

	return err
}

//----Listing Methods----//

// Lists all projects that a user has roles in.
func (repo *repo) listUserProjs(username string) ([]string, error) {
	//auth0 hook
	var uid string
	_, err := repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		return []string{}, err
	}

	projmap := make(map[string]bool)

	var projids []string
	_, err = repo.db.Query(&projids, `SELECT proj FROM projroles WHERE "user" = ?`, uid)
	if err != nil {
		return []string{}, err
	}

	for projid := range projids {
		var proj string
		_, err = repo.db.QueryOne(&proj, `SELECT name FROM projs WHERE id = ?`, projid)
		projmap[proj] = true
	}

	var orgids []string
	_, err = repo.db.Query(&orgids, `SELECT org FROM orgroles WHERE "user" = ?`, uid)
	if err != nil {
		return []string{}, err
	}
	for _, orgid := range orgids {
		var projs []string
		_, err = repo.db.Query(&projs, `SELECT name FROM projs, where org = ?`, orgid)
		if err != nil {
			return []string{}, err
		}
		for _, proj := range projs {
			projmap[proj] = true
		}
	}

	projs := make([]string, 0, len(projmap))
	for proj := range projmap {
		projs = append(projs, proj)
	}

	return projs, err
}

// Lists all organisations that a user has roles in.
func (repo *repo) listUserOrgs(username string) ([]string, error) {
	//auth0 hook
	var uid string
	_, err := repo.db.QueryOne(&uid, `SELECT id FROM users WHERE name = ?`, username)
	if err != nil {
		return []string{}, err
	}

	var orgids []string
	_, err = repo.db.Query(&orgids, `SELECT org FROM orgroles WHERE "user" = ?`, uid)
	if err != nil {
		return []string{}, err
	}

	orgs := make([]string, 0, len(orgids))
	var org string
	for _, orgid := range orgids {
		_, err = repo.db.QueryOne(&org, `SELECT name FROM orgs WHERE id = ?`, orgid)
		if err != nil {
			return []string{}, err
		}
		orgs = append(orgs, org)
	}

	return orgs, err
}

// Lists all users that have roles in a project.
func (repo *repo) listProjUsers(projname string) ([]string, error) {
	var proj Proj
	_, err := repo.db.QueryOne(&proj, `SELECT id, org FROM projs WHERE name = ?`, projname)
	if err != nil {
		return []string{}, err
	}
	projid := proj.Id
	orgid := proj.Org

	if !remote.IsAuthz(repo.token, projid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return []string{}, err
	}

	var uids []string
	_, err = repo.db.Query(&uids, `SELECT "user" FROM projroles WHERE proj = ?`, projid)
	if err != nil {
		return []string{}, err
	}

	var uids2 []string
	_, err = repo.db.Query(&uids2, `SELECT "user" FROM orgroles WHERE org = ?`, orgid)
	if err != nil {
		return []string{}, err
	}

	uids = append(uids, uids2...)

	var user string
	users := make([]string, 0, len(uids))
	for _, uid := range uids {
		_, err = repo.db.QueryOne(&user, `SELECT name FROM users WHERE id = ?`, uid)
		if err != nil {
			return []string{}, err
		}
		users = append(users, user)
	}

	return users, err
}

// List all users that have roles in an organisation.
func (repo *repo) listOrgUsers(orgname string) ([]string, error) {
	var orgid string
	_, err := repo.db.QueryOne(&orgid, `SELECT id FROM orgs WHERE name = ?`, orgname)
	if err != nil {
		return []string{}, err
	}

	if !remote.IsAuthz(repo.token, orgid) { //add perm reqs?
		err = errors.New("Unauthorised")
		repo.log.Debug(err)
		return []string{}, err
	}

	var uids []string
	_, err = repo.db.Query(&uids, `SELECT "user" FROM orgroles WHERE org = ?`, orgid)
	if err != nil {
		return []string{}, err
	}

	var user string
	users := make([]string, 0, len(uids))
	for _, uid := range uids {
		_, err = repo.db.QueryOne(&user, `SELECT name FROM users WHERE id = ?`, uid)
		if err != nil {
			return []string{}, err
		}
		users = append(users, user)
	}

	return users, err
}
