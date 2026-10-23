package store

// OwnerUser — chủ instance mà phiên SSO của Console mở dưới tên (CON-13).

import (
	"errors"
	"testing"
)

// Chuỗi trần thay vì authz.Scope: package authz import store, nên test trong
// package store không import ngược lại được. Giá của nó là hai chuỗi phải khớp
// nhau bằng tay — và chính vì thế phép lọc bên dưới khớp CẢ Ô, không phải
// chuỗi con.
const scopeAdmin = "admin"

func TestOwnerUserPicksTheOldestLiveAdmin(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	ctx := t.Context()

	if _, err := st.OwnerUser(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("máy chưa có ai = %v, muốn ErrNotFound", err)
	}

	mk := func(id, name string, scopes []string, disabled bool) {
		t.Helper()
		if err := st.CreateUser(ctx, &User{
			ID: id, Username: name, PasswordHash: "x", Scopes: scopes, Disabled: disabled,
		}); err != nil {
			t.Fatalf("CreateUser %s: %v", id, err)
		}
	}
	// Người dùng thường KHÔNG phải chủ: một phiên SSO rơi vào tài khoản chỉ có
	// quyền đọc app là một cửa "Mở Admin ↗" mở ra một giao diện trống.
	mk("u-reader", "reader", []string{"apps:read"}, false)
	// Chủ cũ đã bị vô hiệu vẫn phải bị bỏ qua — vô hiệu hoá một tài khoản mà
	// nó vẫn nhận được phiên là vô hiệu hoá trên giấy.
	mk("u-old", "old-owner", []string{scopeAdmin}, true)
	mk("u-owner", "vincent", []string{"apps:read", scopeAdmin}, false)
	mk("u-second", "second", []string{scopeAdmin}, false)

	u, err := st.OwnerUser(ctx)
	if err != nil {
		t.Fatalf("OwnerUser: %v", err)
	}
	if u.ID != "u-owner" {
		t.Errorf("chủ = %q, muốn u-owner (admin còn hiệu lực, cũ nhất)", u.ID)
	}
}

// Scope là chuỗi nối bằng dấu phẩy, nên phép lọc phải khớp CẢ Ô chứ không phải
// chuỗi con: một scope tên `admin-read` mai này không được biến chủ nhân của nó
// thành chủ instance.
func TestOwnerUserDoesNotMatchScopeSubstrings(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	ctx := t.Context()

	if err := st.CreateUser(ctx, &User{
		ID: "u-1", Username: "gần-giống", PasswordHash: "x",
		Scopes: []string{"admin-read", "notadmin"},
	}); err != nil {
		t.Fatal(err)
	}
	if u, err := st.OwnerUser(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OwnerUser = %v (%v), muốn ErrNotFound", u, err)
	}
}
