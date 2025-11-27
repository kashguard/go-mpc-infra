package db_test

import (
	"database/sql"
	"testing"

	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/queries"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/kashguard/go-mpc-wallet/internal/models"
	"github.com/kashguard/go-mpc-wallet/internal/test"
	"github.com/kashguard/go-mpc-wallet/internal/test/fixtures"
	"github.com/kashguard/go-mpc-wallet/internal/util/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInnerJoinWithFilter(t *testing.T) {
	test.WithTestDatabase(t, func(sqlDB *sql.DB) {
		ctx := t.Context()
		fix := fixtures.Fixtures()

		profiles, err := models.AppUserProfiles(db.InnerJoinWithFilter(models.TableNames.AppUserProfiles,
			models.AppUserProfileColumns.UserID,
			models.TableNames.Users,
			models.UserColumns.ID,
			models.UserColumns.Username,
			"user1@example.com",
		)).All(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, profiles, 1)

		assert.Equal(t, fix.User1AppUserProfile.UserID, profiles[0].UserID)

		profiles, err = models.AppUserProfiles(db.InnerJoinWithFilter(models.TableNames.AppUserProfiles,
			models.AppUserProfileColumns.UserID,
			models.TableNames.Users,
			models.UserColumns.ID,
			models.UserColumns.Username,
			"user1@example.com",
			models.TableNames.Users,
		)).All(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, profiles, 1)

		assert.Equal(t, fix.User1AppUserProfile.UserID, profiles[0].UserID)
	})
}

func TestInnerJoin(t *testing.T) {
	test.WithTestDatabase(t, func(sqlDB *sql.DB) {
		ctx := t.Context()
		fix := fixtures.Fixtures()

		profiles, err := models.AppUserProfiles(db.InnerJoin(models.TableNames.AppUserProfiles,
			models.AppUserProfileColumns.UserID,
			models.TableNames.Users,
			models.UserColumns.ID,
		),
			models.UserWhere.Username.EQ(null.StringFrom("user1@example.com")),
		).All(ctx, sqlDB)
		require.NoError(t, err)
		require.Len(t, profiles, 1)

		assert.Equal(t, fix.User1AppUserProfile.UserID, profiles[0].UserID)
	})
}

func TestLeftOuterJoinWithFilter(t *testing.T) {
	query := models.NewQuery(
		qm.Select("*"),
		qm.From("users"),
		db.LeftOuterJoinWithFilter("users", "id", "app_user_profiles", "user_id", "first_name", "Max"),
	)

	sql, args := queries.BuildQuery(query)

	test.Snapshoter.Label("SQL").Save(t, sql)
	test.Snapshoter.Label("Args").Save(t, args...)

	query = models.NewQuery(
		qm.Select("*"),
		qm.From("users"),
		db.LeftOuterJoinWithFilter("users", "id", "app_user_profiles", "user_id", "first_name", "Max", "app_user_profiles"),
	)

	sql, args = queries.BuildQuery(query)

	test.Snapshoter.Label("SQL").Save(t, sql)
	test.Snapshoter.Label("Args").Save(t, args...)
}

func TestLeftOuterJoin(t *testing.T) {
	query := models.NewQuery(
		qm.Select("*"),
		qm.From("users"),
		db.LeftOuterJoin("users", "id", "app_user_profiles", "user_id"),
	)

	sql, args := queries.BuildQuery(query)

	test.Snapshoter.Label("SQL").Save(t, sql)
	test.Snapshoter.Label("Args").Save(t, args...)
}
