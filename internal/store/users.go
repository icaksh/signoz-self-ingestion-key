package store

import (
	"context"
	"database/sql"
)

// GetUserByUsername returns the user's ID and bcrypt password hash, or
// (0, "", nil) when the username does not exist.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (id int64, passwordHash string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT id, password FROM users WHERE username = ?`, username,
	).Scan(&id, &passwordHash)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	return
}

// GetUserByID returns the username for a user ID, or (false) when absent.
// Used to re-validate sessions after a user is deleted.
func (s *Store) GetUserByID(ctx context.Context, id int64) (username string, found bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE id = ?`, id,
	).Scan(&username)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return username, true, nil
}

// CreateUser inserts a new admin user with a pre-hashed password.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password) VALUES (?, ?)`, username, passwordHash)
	return err
}

// ListUsers returns all users, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser removes an admin user.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// UserCount returns the number of admin users.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}
