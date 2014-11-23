<?php

namespace Keycard\Acl;

trait AclTrait
{

	public function addPermission( $name, $value = false )
	{
		if ( isset( $this->permissions ) )
		{
			$this->permissions = array_merge( $this->permissions, is_array( $name ) ? $name : array( $name => $value )  );
		}

		return $this;
	}

	public function deletePermission( $value )
	{
		if ( isset( $this->permissions ) )
		{
			$this->permissions = array_diff_key( $this->permissions, array_fill_keys( $this->normalizePermissions( $value ), 1 ) );
		}

		return $this;
	}

	public function hasAccess( $permissions )
	{
		return $this->inPermission( $permissions, $this->getGrantedPermissions(), false );
	}

	public function hasAnyAccess( $permissions )
	{
		return $this->inPermission( $permissions, $this->getGrantedPermissions(), true );
	}

	public function getGrantedPermissions()
	{
		$grantedPermissions = array();

		if ( is_callable( array( $this, 'roles' ) ) )
		{
			$roles = $this->roles();

			if ( is_callable( array( $roles, 'get' ) ) )
			{
				$roles = $roles->get();

				foreach ( $roles AS $role )
				{
					$rolePermissions = $role->permissions;

					foreach ( $rolePermissions AS $rolePermission => $rolePermissionAllowed )
					{
						if ( empty( $grantedPermissions[ $rolePermission ] ) )
						{
							$grantedPermissions[ $rolePermission ] = $rolePermissionAllowed;
						}
					}
				}
			}
		}

		if ( isset( $this->permissions ) )
		{
			$premissions = $this->permissions;

			foreach ( $premissions AS $premission => $premissionAllowed )
			{
				$grantedPermissions[ $premission ] = $premissionAllowed;
			}
		}

		return $grantedPermissions;
	}

	public function getPermissionsAttribute( $values )
	{
		return $this->sanitizePermissions( \Keycard\Support\Arr::jsonDecode( '{' . $values . '}' ) );
	}

	public function setPermissionsAttribute( array $values )
	{
		$this->attributes[ 'permissions' ] = rtrim( ltrim( \Keycard\Support\Arr::jsonEncode( $this->sanitizePermissions( $values ) ), '{[' ), ']}' );
	}

	protected function inPermission( $permissions, $grantedPermissions, $any = false )
	{
		$permissions = $this->normalizePermissions( $permissions );
		$grantedPermissions = $this->sanitizePermissions( $grantedPermissions );

		uksort( $grantedPermissions, create_function( '$a, $b', 'return strlen( str_replace( "*", "", $a ) ) < strlen( str_replace( "*", "", $b ) );' ) );

		foreach ( $permissions AS $permission )
		{
			$allowed = false;

			if ( isset( $grantedPermissions[ $permission ] ) )
			{
				$allowed = $grantedPermissions[ $permission ];
			}
			elseif ( strlen( trim( $permission, '*' ) ) )
			{
				$permissionPattern = '/^' . implode( '.+?', array_map( 'preg_quote', preg_split( '/\*+/', $permission ) ) ) . '$/';

				foreach ( $grantedPermissions AS $grantedPermission => $grantedPermissionAllowed )
				{
					if ( strlen( trim( $grantedPermission, '*' ) ) )
					{
						$grantedPermissionPattern = '/^' . implode( '.+?', array_map( 'preg_quote', preg_split( '/\*+/', $grantedPermission ) ) ) . '$/';

						if ( preg_match( $permissionPattern, $grantedPermission ) || preg_match( $grantedPermissionPattern, $permission ) )
						{
							$allowed = $grantedPermissionAllowed;
							break;
						}
					}
				}
			}

			if ( !$any && !$allowed )
			{
				return false;
			}
			elseif ( $any && $allowed )
			{
				return true;
			}
		}

		if ( $any )
		{
			return false;
		}

		return true;
	}

	protected function sanitizePermissions( array $values )
	{
		$permissions = array();

		foreach ( $values AS $names => $value )
		{
			$names = $this->normalizePermissions( $names );

			foreach ( $names AS $name )
			{
				$permissions[ $name ] = $value ? 1 : 0;
			}
		}

		return $permissions;
	}

	protected function normalizePermissions( $value )
	{
		return array_map( 'strtolower', explode( ',', is_array( $value ) ? implode( ',', $value ) : $value  ) );
	}

}
