<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;
use Objectiveweb\Auth\Middleware\RequireRole;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Router\Middleware;

/**
 * Reusable, admin-only JSON user-management API.
 *
 * Router examples:
 * GET    /api/users
 * GET    /api/users/roles
 * GET    /api/users/12
 * POST   /api/users
 * PUT    /api/users/12
 * POST   /api/users/12/credentials
 * PUT    /api/users/12/credentials
 * DELETE /api/users/12/credentials/local/name@example.com
 * POST   /api/users/12/suspend|activate|password-reset|invite
 */
#[Middleware(RequireRole::class, ['admin'])]
class UserController
{
    private array $allowedSortFields;

    public function __construct(public Auth $auth)
    {
        $this->allowedSortFields = array_values(array_unique(array_filter([
            $this->auth->params['id'],
            'name',
            $this->auth->params['created'],
            $this->auth->params['last_login'],
            $this->auth->params['disabled_at'],
        ])));
    }

    public function index(array $params = []): array
    {
        return $this->list($params);
    }

    public function get(mixed $userOrParams = [], mixed $resource = null, array $params = []): array
    {
        if (is_array($userOrParams)) {
            return $this->list($userOrParams);
        }
        if ($resource === 'credentials') {
            return ['credentials' => $this->auth->get_credentials($userOrParams)];
        }
        return $this->detail($userOrParams);
    }

    public function getRoles(array $params = []): array
    {
        return [
            'roles' => $this->auth->get_roles(),
            '_csrf' => $this->auth->management_csrf_token(),
        ];
    }

    public function post(mixed $userOrData, mixed $resource = null, ?array $data = null): array
    {
        $this->assertManagementWrite();
        if (is_array($userOrData)) {
            return $this->create($userOrData);
        }
        $data ??= [];
        return match ((string) $resource) {
            'credentials' => $this->createCredential($userOrData, $data),
            'suspend' => $this->setSuspended($userOrData, true),
            'activate' => $this->setSuspended($userOrData, false),
            'password-reset' => $this->sendToken($userOrData, true),
            'invite' => $this->sendToken($userOrData, false),
            default => throw new UserException('Invalid user action', 404),
        };
    }

    public function put(mixed $userId, mixed $resourceOrData, ?array $data = null): array
    {
        $this->assertManagementWrite();
        if (is_array($resourceOrData)) {
            return $this->updateUser($userId, $resourceOrData);
        }
        if ($resourceOrData === 'credentials') {
            return $this->renameCredential($userId, $data ?? []);
        }
        throw new UserException('Invalid user action', 404);
    }

    public function delete(
        mixed $userId,
        mixed $resource = null,
        mixed $provider = null,
        mixed $uid = null,
        array $params = []
    ): array {
        $this->assertManagementWrite();
        if ($resource === 'credentials') {
            $provider = rawurldecode((string) $provider);
            $uid = rawurldecode((string) $uid);
            $this->auth->delete_credential($userId, $provider, $uid);
            $this->auth->audit('credential.deleted', $userId, ['provider' => $provider]);
            return ['ok' => true];
        }

        $this->assertNotSelf($userId, 'delete');
        $target = $this->auth->get($userId);
        $this->assertNotFinalActiveAdmin($target);
        try {
            $this->auth->delete($userId);
        } catch (UserException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new UserException('User has application history; suspend the account instead', 409, $exception);
        }
        return ['ok' => true];
    }

    private function list(array $params): array
    {
        $allowed = ['q', 'role', 'status', 'page', 'size', 'sort'];
        foreach (array_keys($params) as $field) {
            if (!in_array((string) $field, $allowed, true)) {
                throw new UserException("Invalid filter `$field`", 400);
            }
        }
        $params['page'] = max(0, (int) ($params['page'] ?? 0));
        $params['size'] = min(100, max(1, (int) ($params['size'] ?? 20)));
        $params['sort'] = $this->sanitizeSort((string) ($params['sort'] ?? ($this->auth->params['id'] . ' ASC')));
        if (!in_array((string) ($params['status'] ?? ''), ['', 'active', 'suspended'], true)) {
            throw new UserException('Invalid status filter', 400);
        }
        $result = $this->auth->query($params, 'AND');
        $key = $this->auth->params['table'];
        $result['_embedded'][$key] = array_map(
            fn (array $user): array => $this->sanitizeUser($user),
            $result['_embedded'][$key] ?? []
        );
        $result['_csrf'] = $this->auth->management_csrf_token();
        return $result;
    }

    private function detail(mixed $userId): array
    {
        $user = $this->sanitizeUser($this->auth->get($userId));
        $user['credentials'] = $this->auth->get_credentials($userId);
        $user['managed_relations'] = $this->auth->get_managed_relations($userId);
        $user['status'] = $this->auth->is_active($user) ? 'active' : 'suspended';
        $user['_csrf'] = $this->auth->management_csrf_token();
        return $user;
    }

    private function create(array $data): array
    {
        $uid = trim((string) ($data['uid'] ?? ''));
        if ($uid === '') {
            throw new UserException('Missing uid', 400);
        }
        $relations = $data['managed_relations'] ?? [];
        unset($data['managed_relations'], $data['uid']);
        $passwordField = $this->auth->params['password'];
        $password = $data[$passwordField] ?? null;
        unset($data[$passwordField]);
        $this->assertWriteFields($data);
        $this->assertKnownRoles((array) ($data[$this->auth->params['roles']] ?? []));

        $user = $this->auth->register($uid, is_string($password) && $password !== '' ? $password : null, $data);
        $id = $user[$this->auth->params['id']];
        if (is_array($relations) && $relations !== []) {
            $this->auth->sync_managed_relations($id, $relations);
        }
        if (!is_string($password) || $password === '') {
            $this->auth->invite($id);
        }
        $this->auth->audit('user.created', $id, [
            'roles' => $user[$this->auth->params['roles']] ?? [],
            'invited' => !is_string($password) || $password === '',
        ]);
        return $this->detail($id);
    }

    private function updateUser(mixed $userId, array $data): array
    {
        $target = $this->auth->get($userId);
        $relationsPresent = array_key_exists('managed_relations', $data);
        $relations = $data['managed_relations'] ?? [];
        unset($data['managed_relations'], $data['uid'], $data[$this->auth->params['password']]);
        $this->assertWriteFields($data);

        $roleField = $this->auth->params['roles'];
        if (array_key_exists($roleField, $data)) {
            $roles = is_array($data[$roleField]) ? $data[$roleField] : [];
            $this->assertKnownRoles($roles);
            $this->assertOwnAdminRolePreserved($userId, $roles);
            if (in_array('admin', (array) ($target[$roleField] ?? []), true) && !in_array('admin', $roles, true)) {
                $this->assertNotFinalActiveAdmin($target);
            }
        }

        $this->auth->update($userId, $data);
        if ($relationsPresent) {
            if (!is_array($relations)) {
                throw new UserException('Invalid managed relations', 400);
            }
            $this->auth->sync_managed_relations($userId, $relations);
        }
        $this->auth->audit('user.updated', $userId, ['fields' => array_keys($data)]);
        return $this->detail($userId);
    }

    private function createCredential(mixed $userId, array $data): array
    {
        $credential = $this->auth->create_credential(
            $userId,
            (string) ($data['provider'] ?? ''),
            (string) ($data['uid'] ?? ''),
            $data['profile'] ?? null
        );
        $this->auth->audit('credential.created', $userId, ['provider' => $credential['provider'] ?? null]);
        return ['credential' => $this->sanitizeCredential($credential)];
    }

    private function renameCredential(mixed $userId, array $data): array
    {
        $credential = $this->auth->rename_credential(
            $userId,
            (string) ($data['provider'] ?? ''),
            (string) ($data['uid'] ?? ''),
            (string) ($data['new_provider'] ?? $data['provider'] ?? ''),
            (string) ($data['new_uid'] ?? '')
        );
        $this->auth->audit('credential.renamed', $userId, ['provider' => $credential['provider'] ?? null]);
        return ['credential' => $this->sanitizeCredential($credential)];
    }

    private function setSuspended(mixed $userId, bool $suspended): array
    {
        $field = $this->auth->params['disabled_at'];
        if (!is_string($field) || $field === '') {
            throw new UserException('Lifecycle state is disabled', 400);
        }
        if ($suspended) {
            $this->assertNotSelf($userId, 'suspend');
            $this->assertNotFinalActiveAdmin($this->auth->get($userId));
        }
        $this->auth->update($userId, [$field => $suspended ? date('Y-m-d H:i:s') : null]);
        $this->auth->audit($suspended ? 'user.suspended' : 'user.activated', $userId);
        return $this->detail($userId);
    }

    private function sendToken(mixed $userId, bool $reset): array
    {
        $this->auth->invite($userId, $reset);
        $this->auth->audit($reset ? 'password.reset_requested' : 'invitation.sent', $userId);
        return ['ok' => true];
    }

    private function assertManagementWrite(): void
    {
        if (!$this->auth->params['management_csrf']) {
            return;
        }
        // Direct service/controller calls in tests have no request method. HTTP
        // requests must always be JSON and carry the session-bound token.
        if (empty($_SERVER['REQUEST_METHOD'])) {
            return;
        }
        $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
        if (!str_contains($contentType, 'application/json')) {
            throw new UserException('Content-Type application/json is required', 415);
        }
        $provided = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        $expected = $this->auth->management_csrf_token();
        if ($provided === '' || !hash_equals($expected, $provided)) {
            throw new UserException('Invalid CSRF token', 403);
        }
    }

    private function assertKnownRoles(array $roles): void
    {
        $unknown = array_values(array_diff($roles, $this->auth->get_roles()));
        if ($unknown !== []) {
            throw new UserException('Unknown role `' . (string) $unknown[0] . '`', 400);
        }
    }

    private function assertNotSelf(mixed $userId, string $action): void
    {
        $current = $this->auth->user();
        if (($current[$this->auth->params['id']] ?? null) == $userId) {
            throw new UserException("Cannot $action your own account", 409);
        }
    }

    private function assertOwnAdminRolePreserved(mixed $userId, array $roles): void
    {
        $current = $this->auth->user();
        if (
            ($current[$this->auth->params['id']] ?? null) == $userId
            && in_array('admin', (array) ($current[$this->auth->params['roles']] ?? []), true)
            && !in_array('admin', $roles, true)
        ) {
            throw new UserException('Cannot remove your own admin role', 409);
        }
    }

    private function assertNotFinalActiveAdmin(array $target): void
    {
        if (
            !in_array('admin', (array) ($target[$this->auth->params['roles']] ?? []), true)
            || !$this->auth->is_active($target)
        ) {
            return;
        }
        $activeAdmins = array_filter(
            $this->auth->get_users_by_role('admin'),
            fn (array $user): bool => $this->auth->is_active($user)
        );
        if (count($activeAdmins) <= 1) {
            throw new UserException('Cannot remove or suspend the final active administrator', 409);
        }
    }

    private function assertWriteFields(array $data): void
    {
        $allowed = array_values(array_unique(array_filter([
            'name',
            'image',
            'provider',
            'profile',
            $this->auth->params['roles'],
            $this->auth->params['disabled_at'],
        ])));
        foreach (array_keys($data) as $field) {
            if (!in_array((string) $field, $allowed, true)) {
                throw new UserException("Invalid field `$field`", 400);
            }
        }
    }

    private function sanitizeSort(string $sort): string
    {
        [$field, $direction] = array_pad(preg_split('/\s+/', trim($sort), 2), 2, 'ASC');
        if (!in_array($field, $this->allowedSortFields, true)) {
            throw new UserException("Invalid sort field `$field`", 400);
        }
        $direction = strtoupper($direction);
        if (!in_array($direction, ['ASC', 'DESC'], true)) {
            throw new UserException("Invalid sort direction `$direction`", 400);
        }
        return $field . ' ' . $direction;
    }

    private function sanitizeUser(array $user): array
    {
        unset($user[$this->auth->params['password']]);
        if ($this->auth->params['token']) {
            unset($user[$this->auth->params['token']]);
        }
        $expires = $this->auth->params['token_expires_field'];
        if (is_string($expires) && $expires !== '') {
            unset($user[$expires]);
        }
        if (isset($user['credentials']) && is_array($user['credentials'])) {
            $user['credentials'] = array_map([$this, 'sanitizeCredential'], $user['credentials']);
        }
        return $user;
    }

    private function sanitizeCredential(array $credential): array
    {
        unset($credential['token'], $credential['user_id']);
        if (isset($credential['profile']['_auth'])) {
            unset($credential['profile']['_auth']['token']);
        }
        return $credential;
    }
}
