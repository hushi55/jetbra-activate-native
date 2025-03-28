package main

import (
	"github.com/atotto/clipboard"
	"testing"
)

func TestGenActivateCode(t *testing.T) {
	// 初始化加密工具
	cu, err := NewCryptoUtil()
	if err != nil {
		t.Fatalf("初始化加密工具失败: %v", err)
	}

	// 生成激活码
	licenseName := GetLicenseName()
	expireDate := "2099-09-14"
	code, err := cu.GenActivateCode(licenseName, expireDate, "PFASTREQUEST")

	t.Logf("激活码: %s", code)

	err = clipboard.WriteAll(code)
	if err == nil {
		t.Logf("（已复制到剪贴板）")
	}

}

// 辅助函数：分割激活码各部分
//func splitCodeParts(t *testing.T, code string) []string {
//	parts := make([]string, 4)
//	for i, part := range strings.Split(code, "-") {
//		if i >= 4 {
//			t.Fatal("激活码格式不正确，应有4个部分")
//		}
//		parts[i] = part
//	}
//	return parts
//}

// 辅助函数：验证签名
//func verifySignature(t *testing.T, cu *CryptoUtil, parts []string) {
//	licenseRaw, _ := base64.StdEncoding.DecodeString(parts[1])
//	signature, _ := base64.StdEncoding.DecodeString(parts[2])
//
//	hashed := sha1.Sum(licenseRaw)
//	err := rsa.VerifyPKCS1v15(cu.pubKey, crypto.SHA1, hashed[:], signature)
//	if err != nil {
//		t.Fatalf("签名验证失败: %v", err)
//	}
//}

// 辅助函数：验证许可证信息
//func verifyLicenseInfo(t *testing.T, b64License string, expectedName, expectedDate string, expectedProducts []Product) {
//	licenseRaw, err := base64.StdEncoding.DecodeString(b64License)
//	if err != nil {
//		t.Fatalf("许可证解码失败: %v", err)
//	}
//
//	license, err := ParseLicenseRaw(licenseRaw)
//	if err != nil {
//		t.Fatalf("许可证解析失败: %v", err)
//	}
//
//	if license.LicenseName != expectedName {
//		t.Errorf("期望用户名 %q，实际 %q", expectedName, license.LicenseName)
//	}
//	if license.ExpireDate != expectedDate {
//		t.Errorf("期望过期日期 %q，实际 %q", expectedDate, license.ExpireDate)
//	}
//	if len(license.Products) != len(expectedProducts) {
//		t.Errorf("期望产品数量 %d，实际 %d", len(expectedProducts), len(license.Products))
//	}
//}
