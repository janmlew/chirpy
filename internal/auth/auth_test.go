package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "correct-horse-battery-staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned an empty hash")
	}
	if hash == password {
		t.Fatal("HashPassword returned the plaintext password")
	}
}

func TestHashPasswordUsesRandomSalt(t *testing.T) {
	password := "04234"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	// Argon2id salts each hash randomly, so the same password must
	// produce different hashes — yet both must still verify.
	if hash1 == hash2 {
		t.Fatal("hashing the same password twice produced identical hashes (no random salt?)")
	}
	for _, h := range []string{hash1, hash2} {
		match, err := CheckPasswordHash(password, h)
		if err != nil {
			t.Fatalf("CheckPasswordHash returned an error: %v", err)
		}
		if !match {
			t.Fatal("a freshly created hash failed to verify against its own password")
		}
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "04234"
	otherPassword := "different-password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("setup: HashPassword returned an error: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		hash      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "correct password",
			password:  password,
			hash:      hash,
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "wrong password",
			password:  otherPassword,
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "empty password against real hash",
			password:  "",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "malformed hash returns an error",
			password:  password,
			hash:      "not-a-valid-argon2id-hash",
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			if match != tt.wantMatch {
				t.Fatalf("CheckPasswordHash() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}
