package main

import (
	"encoding/json"
	"math/rand"
	"os/user"
	"strings"
)

var JetProducts = []Product{
	Product("II"), // idea
	Product("CL"), // clion
	Product("PS"), // phpstorm
	Product("GO"), // goland
	Product("PC"), // pycharm
	Product("WS"), // webstorm
	Product("RD"), // rider
	Product("DB"), // datagrip
	//Product("RM"), // rubymine
	//Product("AC"), // appcode
	Product("DS"), // dataspell
}

type Product string

type ProductAuth struct {
	Code         string `json:"code"`
	FallBackDate string `json:"fallBackDate"`
	PaidUpTo     string `json:"paidUpTo"`
	Extend       bool   `json:"extend"`
}

type License struct {
	LicenseID          string        `json:"licenseId"`
	LicenseeName       string        `json:"licenseeName"`
	AssigneeName       string        `json:"assigneeName"`
	AssigneeEmail      string        `json:"assigneeEmail"`
	LicenseRestriction string        `json:"licenseRestriction"`
	CheckConcurrentUse bool          `json:"checkConcurrentUse"`
	Products           []ProductAuth `json:"products"`
	Metadata           string        `json:"metadata"`
	Hash               string        `json:"hash"`
	GracePeriodDays    int           `json:"gracePeriodDays"`
	AutoProlongated    bool          `json:"autoProlongated"`
	IsAutoProlongated  bool          `json:"isAutoProlongated"`
}

func (l License) Raw() []byte {
	raw, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}

	return raw
}

func NewLicense(licenseName string, expireDate string, products ...Product) License {
	l := License{
		LicenseID:       strings.ToUpper(randStr(10)),
		LicenseeName:    licenseName,
		Metadata:        "0120230914PSAX000005",
		Hash:            "TRIAL:-1635216578",
		GracePeriodDays: 7,
	}

	for _, product := range products {
		productAuth := ProductAuth{
			Code:         string(product),
			FallBackDate: expireDate,
			PaidUpTo:     expireDate,
			Extend:       true,
		}

		l.Products = append(l.Products, productAuth)
	}

	return l
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func GetLicenseName() string {
	var licenseName string

	cUser, _ := user.Current()
	if cUser != nil {
		licenseName = cUser.Name
		if licenseName == "" {
			licenseName = cUser.Username
		}
	}

	if licenseName == "" {
		licenseName = randStr(10)
	}

	return licenseName
}
