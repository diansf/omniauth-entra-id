# Upgrading from `omniauth-azure-activedirectory-v2`

This guide assumes you were on v2.3 or v2.4 of the old-named gem. The basic steps are:

* Update your code to account for the rename
* Update your code to account for breaking changes



## Updates due to the gem rename

All gem users will likely need to follow these steps.

* In general, searching project-wide for `azure_activedirectory_v2` and replacing with `entra_id` and, likewise, for the hyphenated `azure-activedirectory-v2` and replacing with `entra-id`, will cover a lot of use cases
* `README.md` always included examples with environment variables that were named as illustrations only; these have changed from e.g. `AZURE_CLIENT_ID` to `ENTRA_CLIENT_ID` just for internal consistency, but while renaming your own related environment variables or constants (should you use any) may help with code base understanding and consistency, it's not essential. Those names are part of _your_ code base, not part of code in this gem.

### Configuration

Rename the strategy in your configuration block:

```ruby
config.omniauth(
  :azure_activedirectory_v2,
  # ...
)
```

...becomes:

```ruby
config.omniauth(
  :entra_id,
  # ...
)
```

### Callback routes

Depending on how you handle callbacks from OmniAuth, you might need to update routes or controllers handling shared routes to account for the name change. The old callback URL of:

```
https://example.com/v1/auth/azure_activedirectory_v2/callback
```

...is now:

```
https://example.com/v1/auth/entra_id/callback
```

### URL generation

Change things like this:

```
omniauth_authorize_url('resource_name_eg_user', 'azure_activedirectory_v2', scope: '...')
```

...to this:

```
omniauth_authorize_url('resource_name_eg_user', 'entra_id', scope: '...')
```



## Updates due to other breaking changes
### Change affecting all gem users
#### UIDs will change

This change is for UIDs and is the main reason for creating a V3 gem, whether or not it included the Entra name change.

* The UID returned by OmniAuth for a user previously depended upon the `oid` (object ID) returned by Microsoft. As noted in #33 and fixed in #34, this _might not be unique_ and tenant ID (`tid`) is supposed to be considered too.
* Out-of-box, Entra ID will do this. If you were an Azure ActiveDirectory V2 (old-name gem, version 2.x) user, then you will have been receiving different UIDs based only on the `oid` from Microsoft.
* **The change of OID might break the connection between a previously-registered and logged in user and a new login** as usually, you need to store the OmniAuth UID somewhere alongside or within your User records when a user is "connected to" an external OAuth service such as Entra ID.
* **However, there is a strong argument that TID is not needed** - see https://github.com/pond/omniauth-entra-id/issues/42 for a good argument to that end.

You have three options, should the issue affect you (and it almost certainly will).

* If you are confident that you still only need the OID, set the `ignore_tid` option to `true` alongside `client_id` and `client_secret` in your OmniAuth Entra ID initialiser or your custom provider class given to that initialiser, if you use one. See the top-level `README.md` for more.
* If you can determine the tenant IDs for all users in your database, you can just migrate the UIDs. The new UID is just a simple concatenation of tenant ID and object ID, so treating the UID as a string, add the tenant ID as a prefix without any other changes in your migration and things should work fine thereafter.
* Otherwise, you should lazy-migrate:
  - As usual, in your OAuth callback handler, `request.env['omniauth.auth'].uid` gives the UID - but now that's the "new" Entra gem's value which includes tenant ID.
  - If you can find a user with that ID, then all good - they've been migrated already or got connected to Entra *after* you started using the updated gem
  - Otherwise, check `request.env['omniauth.auth'].extra.dig('raw_info', 'oid')` - this gives the value that the *old Azure ActiveDirectory V2 gem* used as UID
  - Look up the user with this ID. If you find them, great; remember to migrate their record by updating their stored auth ID to the new `request.env['omniauth.auth'].uid` value.
  - For better security add something like an indexed boolean column indicating whether or not the user has been thus migrated and only perform old OID lookups on users which have not yet been migrated.
  - If the user can't be found by either means, then they've not been connected to your system yet. Your existing handling path for such a condition applies.

#### Applications that handle multiple OAuth providers

If your user records contain users that have 'connected' to more than one kind of OAuth provider, then as well as the third party's UID being stored for future logins, you'll most likely have stored the OmniAuth provider name too so that the UID can be looked up in a provider's context (there's no guarantee, of course, that UIDs are unique *between providers* since they're entirely independent entities with their own strategies for allocating unique IDs).

In that case, you will need to migrate records from the old `azure_activedirectory_v2` name to `entra_id`. **Zero-downtime deployment of this change would be very hard since your codebase would need to update from the Azure ActiveDirectory V2 gem to the Entra ID gem with the migration running simultaneously**, so if you need to do such a migration, then you probably should plan for a small maintenance window. At the scheduled time, go into maintenance mode, migrate, deploy, and restore normal service. Even without this, though, the 'worst that can happen' (in theory!) would be temporary user login failures. Either the Entra gem will be causing you to look for a user with an `entra_id` provider but the migration to set this hasn't run yet, or the other way round, with the old gem looking for the old provider name but it's already updated.

#### Example migration code

Suppose you support multiple providers and your User table stores their chosen provider in a column `auth_provider`, with their UID in `auth_uid`. An (irreversible) database migration might do this:

```ruby
def up
  add_column :users, :migrated_to_entra, :boolean

  User
    .where(auth_provider: 'azure_activedirectory_v2')
    .update_all(
      auth_provider:     'entra_id',
      migrated_to_entra: false
    )
end

def down
  raise ActiveRecord::IrreversibleMigration
end
```

This means the `migrated_to_entra` column is only ever `false` for existing users that were linked using the V2 gem. Everything else will be at `NULL`. Now you lazy-move those users to the new UID format in the code you use to look up a user in your OmniAuth OAuth 2 callback handler, e.g. via a method such as this:

```ruby
# Here, "raw_info" comes from e.g.:
#
#   request.env['omniauth.auth'].extra&.dig('raw_info') || {}
#
def find_user_for_omniauth(auth_provider:, auth_uid:, raw_info:)
  found_user = User.find_by(
    auth_provider: auth_provider,
    auth_uid:      auth_uid
  )

  if found_user.nil? && auth_provider == 'entra_id'
    found = User.find_by(
      auth_provider:     'entra_id',
      auth_uid:          raw_info['oid'],
      migrated_to_entra: false
    )

    if found
      found.update_columns(
        auth_uid:          auth_uid,
        migrated_to_entra: true
      )
    end
  end

  return found_user
end
```

Once there are no rows with a `migrated_to_entra` value of `false` for _active_ users, you will be able to drop the column and remove the lazy migration code.

### Other changes that might affect you

* If you refer to `OmniAuth::Strategies::AzureActivedirectoryV2` at all, then this becomes `OmniAuth::Strategies::EntraId` (note lower case "d").
* `base_azure_url` option renamed to just `base_url` with corresponding rename of `OmniAuth::Strategies::AzureActivedirectoryV2::BASE_AZURE_URL` to `OmniAuth::Strategies::EntraId::BASE_URL`.
