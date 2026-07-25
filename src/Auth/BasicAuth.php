<?php

namespace Objectiveweb\Auth;

/**
 * Class BasicAuth
 * Basic Auth implementation with hardcoded users
 *
 * @package Objectiveweb\Auth
 */
class BasicAuth extends \Objectiveweb\Auth
{
    private array $users = [];
    private array $credentials = [];

    public function __construct(array $passwd = [], array $params = [])
    {
        $defaults = [
            'table' => 'basic_user',
        ];
        parent::__construct(array_merge($defaults, $params));

        foreach ($passwd as $uid => $password) {
            if (is_array($password)) {
                $row = $password;
                $candidateUid = $row['uid'] ?? (is_string($uid) ? $uid : null);
                if (empty($candidateUid)) {
                    continue;
                }
                $this->register($candidateUid, $row[$this->params['password']] ?? null, $row);
                continue;
            }

            if (!is_string($uid)) {
                continue;
            }

            $this->register($uid, (string) $password);
        }
    }

    public function query($params = array(), $operator = "OR")
    {
        $page = max(0, (int) ($params['page'] ?? 0));
        $size = max(1, (int) ($params['size'] ?? 20));
        $sort = (string) ($params['sort'] ?? ($this->params['id'] . ' ASC'));
        $q = trim((string) ($params['q'] ?? ''));
        $role = trim((string) ($params['role'] ?? ''));
        $status = trim((string) ($params['status'] ?? ''));
        unset($params['page'], $params['size'], $params['sort'], $params['q'], $params['role'], $params['status']);

        $matches = [];
        foreach ($this->users as $row) {
            if (!$this->matchesFilters($row, $params, $operator)) {
                continue;
            }

            $credentials = $this->get_credentials($row[$this->params['id']]);
            if ($q !== '') {
                $haystack = strtolower(implode(' ', array_merge(
                    [(string) ($row['name'] ?? ''), (string) ($row[$this->params['id']] ?? '')],
                    array_map(fn (array $credential): string => (string) $credential['uid'], $credentials)
                )));
                if (!str_contains($haystack, strtolower($q))) {
                    continue;
                }
            }
            $roles = is_array($row[$this->params['roles']] ?? null) ? $row[$this->params['roles']] : [];
            if ($role === 'unassigned' && $roles !== []) {
                continue;
            }
            if ($role !== '' && $role !== 'unassigned' && !in_array($role, $roles, true)) {
                continue;
            }
            if ($status === 'active' && !$this->is_active($row)) {
                continue;
            }
            if ($status === 'suspended' && $this->is_active($row)) {
                continue;
            }
            $public = $this->publicUser($row);
            $public['credentials'] = $credentials;
            $matches[] = $public;
        }

        [$sortField, $sortDirection] = array_pad(preg_split('/\s+/', trim($sort), 2), 2, 'ASC');
        usort($matches, static function (array $a, array $b) use ($sortField, $sortDirection): int {
            $comparison = ($a[$sortField] ?? null) <=> ($b[$sortField] ?? null);
            return strtoupper($sortDirection) === 'DESC' ? -$comparison : $comparison;
        });

        $count = count($matches);
        $slice = array_slice($matches, $page * $size, $size);

        return [
            '_embedded' => [
                $this->params['table'] => $slice,
            ],
            'page' => [
                'size' => $size,
                'number' => $page,
                'totalElements' => $count,
                'totalPages' => (int) ceil($count / $size),
            ],
        ];
    }

    public function get($user_id, $key = 'id')
    {
        $resolved = $this->resolveUserId($user_id, $key);
        if ($resolved === null || !isset($this->users[$resolved])) {
            throw new UserException("User `$user_id` not found", 404);
        }

        return $this->users[$resolved];
    }

    public function &login($uid, $password)
    {
        return parent::login($uid, $password);
    }

    public function register($uid, $password = null, $data = array())
    {
        if (is_array($uid)) {
            $data = array_merge($uid, $data);
            $uid = $data['uid'] ?? null;
            $password = $data[$this->params['password']] ?? null;
            unset($data['uid'], $data[$this->params['password']]);
        }

        if (empty($uid)) {
            throw new UserException('Missing uid', 400);
        }

        $provider = $data['provider'] ?? 'local';
        $profile = $data['profile'] ?? null;
        unset($data['provider'], $data['profile']);

        if ($this->get_credential($provider, $uid)) {
            throw new UserException("User `$uid` already exists", 409);
        }

        $idField = $this->params['id'];
        $userId = $data[$idField] ?? $this->nextId();

        $record = $data;
        $record[$idField] = $userId;
        $record['uid'] = $uid;
        if (is_string($this->params['disabled_at']) && $this->params['disabled_at'] !== '') {
            $record[$this->params['disabled_at']] = $record[$this->params['disabled_at']] ?? null;
        }

        if ($password !== null && $password !== '') {
            $record[$this->params['password']] = $this->isPasswordHash($password)
                ? $password
                : self::hash($password);
        } elseif (!array_key_exists($this->params['password'], $record)) {
            $record[$this->params['password']] = null;
        }

        if (!isset($record['name'])) {
            $parts = explode('@', (string) $uid, 2);
            $record['name'] = $parts[0];
        }

        $this->users[$userId] = $record;
        $this->update_credential($userId, $provider, $uid, $profile);

        return $this->publicUser($record);
    }

    public function passwd($user_id, $password, $key = 'id')
    {
        $resolved = $this->resolveUserId($user_id, $key);
        if ($resolved === null || !isset($this->users[$resolved])) {
            throw new UserException('User not found', 404);
        }

        $this->users[$resolved][$this->params['password']] = self::hash($password);
        return true;
    }

    public function passwd_reset($token, $password)
    {
        $tokenField = $this->params['token'];
        if (empty($tokenField)) {
            throw new UserException('Token support is disabled', 400);
        }

        foreach ($this->users as $userId => $user) {
            $hash = (string) ($user[$tokenField] ?? '');
            if ($hash === '' || !password_verify($token, $hash)) {
                continue;
            }
            $expiresField = $this->params['token_expires_field'];
            if (
                is_string($expiresField)
                && $expiresField !== ''
                && !empty($user[$expiresField])
                && strtotime((string) $user[$expiresField]) < time()
            ) {
                continue;
            }

            $this->users[$userId][$this->params['password']] = self::hash($password);
            $this->users[$userId][$tokenField] = null;
            if (is_string($expiresField) && $expiresField !== '') {
                $this->users[$userId][$expiresField] = null;
            }

            return $this->publicUser($this->users[$userId]);
        }

        throw new UserException('Hash not found', 404);
    }

    public function update($user_id, array $data, $key = 'id')
    {
        $resolved = $this->resolveUserId($user_id, $key);
        if ($resolved === null || !isset($this->users[$resolved])) {
            throw new UserException('User not found', 404);
        }

        unset($data[$this->params['id']], $data[$this->params['password']]);
        if ($this->params['token']) {
            unset($data[$this->params['token']]);
        }

        foreach ($data as $field => $value) {
            $this->users[$resolved][$field] = $value;
        }
    }

    public function delete($user_id)
    {
        $resolved = $this->resolveUserId($user_id, $this->params['id']);
        if ($resolved === null || !isset($this->users[$resolved])) {
            throw new UserException('User not found', 404);
        }

        if ($this->check()) {
            $current = $this->user();
            if (($current[$this->params['id']] ?? null) == $resolved) {
                throw new \Exception('Cannot delete yourself!');
            }
        }

        $this->audit('user.deleted', $resolved);
        unset($this->users[$resolved]);
        foreach ($this->credentials as $provider => $records) {
            foreach ($records as $uid => $credential) {
                if (($credential['user_id'] ?? null) == $resolved) {
                    unset($this->credentials[$provider][$uid]);
                }
            }
            if (empty($this->credentials[$provider])) {
                unset($this->credentials[$provider]);
            }
        }

        return true;
    }

    public function update_token($user_id)
    {
        $resolved = $this->resolveUserId($user_id, $this->params['id']);
        if ($resolved === null || !isset($this->users[$resolved])) {
            throw new UserException('Token not found', 404);
        }

        $tokenField = $this->params['token'];
        if (empty($tokenField)) {
            throw new UserException('Token support is disabled', 400);
        }

        $token = self::hash();
        $this->users[$resolved][$tokenField] = self::hash($token);
        $expiresField = $this->params['token_expires_field'];
        if (is_string($expiresField) && $expiresField !== '') {
            $this->users[$resolved][$expiresField] = date(
                'Y-m-d H:i:s',
                time() + max(60, (int) $this->params['token_ttl'])
            );
        }
        return $token;
    }

    public function get_credential($provider, $accountid)
    {
        return $this->credentials[$provider][$accountid] ?? false;
    }

    public function get_credentials($user_id, $key = 'id'): array
    {
        $user = $this->get($user_id, $key);
        $resolvedUserId = $user[$this->params['id']] ?? null;
        $result = [];

        foreach ($this->credentials as $provider => $records) {
            foreach ($records as $uid => $credential) {
                if (($credential['user_id'] ?? null) != $resolvedUserId) {
                    continue;
                }

                $profile = $credential['profile'] ?? null;
                if (is_string($profile) && $profile !== '') {
                    $decoded = json_decode($profile, true);
                    $profile = is_array($decoded) ? $decoded : $profile;
                }

                if (is_array($profile) && isset($profile['_auth']) && is_array($profile['_auth'])) {
                    unset($profile['_auth']['token']);
                }

                $result[] = [
                    'uid' => $uid,
                    'provider' => $provider,
                    'profile' => $profile,
                    'last_login' => $credential['last_login'] ?? null,
                    'created' => $credential['created'] ?? null,
                ];
            }
        }

        usort($result, function (array $a, array $b): int {
            return [$a['provider'], $a['uid']] <=> [$b['provider'], $b['uid']];
        });

        return $result;
    }

    public function get_users_by_role($roleName): array
    {
        $roleField = $this->params['roles'];
        $matches = [];

        foreach ($this->users as $user) {
            $roles = $user[$roleField] ?? [];
            if (!is_array($roles) || !in_array($roleName, $roles, true)) {
                continue;
            }

            $matches[] = $this->publicUser($user);
        }

        return $matches;
    }

    public function get_roles(): array
    {
        $roleField = $this->params['roles'];
        $roles = [];

        foreach ($this->users as $user) {
            $userRoles = $user[$roleField] ?? [];
            if (!is_array($userRoles)) {
                continue;
            }

            foreach ($userRoles as $role) {
                if (!is_string($role) || $role === '') {
                    continue;
                }
                $roles[$role] = true;
            }
        }

        $result = array_keys($roles);
        sort($result, SORT_STRING);
        return $result;
    }

    public function update_credential($userid, $provider, $uid, $profile = null)
    {
        $existing = $this->get_credential($provider, $uid);
        if ($existing && ($existing['user_id'] ?? null) != $userid) {
            throw new UserException('Credential already registered', 409);
        }
        if (is_array($profile)) {
            $profile = json_encode($profile);
        }

        $created = $this->credentials[$provider][$uid]['created'] ?? date('Y-m-d H:i:s');
        $this->credentials[$provider][$uid] = [
            'user_id' => $userid,
            'provider' => $provider,
            'uid' => $uid,
            'profile' => $profile,
            'last_login' => date('Y-m-d H:i:s'),
            'created' => $created,
        ];

        return true;
    }

    public function create_credential($userid, string $provider, string $uid, mixed $profile = null): array
    {
        $this->get($userid);
        $provider = trim($provider);
        $uid = trim($uid);
        if ($provider === '' || $uid === '') {
            throw new UserException('Provider and uid are required', 400);
        }
        if ($this->get_credential($provider, $uid)) {
            throw new UserException('Credential already registered', 409);
        }
        $this->update_credential($userid, $provider, $uid, $profile);
        return $this->get_credential($provider, $uid);
    }

    public function rename_credential(
        $userid,
        string $provider,
        string $uid,
        string $newProvider,
        string $newUid
    ): array {
        $credential = $this->get_credential($provider, $uid);
        if (!$credential || ($credential['user_id'] ?? null) != $userid) {
            throw new UserException('Credential not found', 404);
        }
        if (($provider !== $newProvider || $uid !== $newUid) && $this->get_credential($newProvider, $newUid)) {
            throw new UserException('Credential already registered', 409);
        }
        unset($this->credentials[$provider][$uid]);
        $this->update_credential($userid, trim($newProvider), trim($newUid), $credential['profile'] ?? null);
        return $this->get_credential($newProvider, $newUid);
    }

    public function delete_credential($userid, string $provider, string $uid): bool
    {
        $credential = $this->get_credential($provider, $uid);
        if (!$credential || ($credential['user_id'] ?? null) != $userid) {
            throw new UserException('Credential not found', 404);
        }
        if (count($this->get_credentials($userid)) <= 1) {
            throw new UserException('A user must have at least one credential', 409);
        }
        unset($this->credentials[$provider][$uid]);
        return true;
    }

    public function get_managed_relations($userId): array
    {
        $this->get($userId);
        $result = [];
        foreach ((array) $this->params['managed_relations'] as $name => $_config) {
            $values = $this->users[$userId]['_managed_relations'][$name] ?? [];
            $result[$name] = array_values($values);
        }
        return $result;
    }

    public function sync_managed_relations($userId, array $relations): array
    {
        $this->get($userId);
        foreach ($relations as $name => $values) {
            if (!isset($this->params['managed_relations'][$name]) || !is_array($values)) {
                throw new UserException("Invalid managed relation `$name`", 400);
            }
            $this->users[$userId]['_managed_relations'][$name] = array_values(array_unique($values));
        }
        return $this->get_managed_relations($userId);
    }

    private function nextId(): int
    {
        if (empty($this->users)) {
            return 1;
        }

        $keys = array_keys($this->users);
        return ((int) max($keys)) + 1;
    }

    private function resolveUserId(mixed $value, string $key): int|string|null
    {
        if ($key === 'id' || $key === $this->params['id']) {
            return $value;
        }

        if ($key === 'uid') {
            foreach ($this->params['login_providers'] as $provider) {
                $credential = $this->get_credential($provider, $value);
                if (!empty($credential['user_id'])) {
                    return $credential['user_id'];
                }
            }

            return null;
        }

        foreach ($this->users as $id => $user) {
            if (($user[$key] ?? null) == $value) {
                return $id;
            }
        }

        return null;
    }

    private function matchesFilters(array $row, array $filters, string $operator): bool
    {
        if (empty($filters)) {
            return true;
        }

        $matches = [];
        foreach ($filters as $field => $value) {
            $rowValue = $row[$field] ?? null;
            if (is_string($value) && str_contains($value, '%')) {
                $pattern = '/^' . str_replace('%', '.*', preg_quote($value, '/')) . '$/i';
                $matches[] = (bool) preg_match($pattern, (string) $rowValue);
                continue;
            }
            $matches[] = ($rowValue == $value);
        }

        if (strtoupper($operator) === 'AND') {
            return !in_array(false, $matches, true);
        }

        return in_array(true, $matches, true);
    }

    private function publicUser(array $user): array
    {
        unset($user['_managed_relations']);
        unset($user[$this->params['password']]);
        if ($this->params['token']) {
            unset($user[$this->params['token']]);
        }
        return $user;
    }

    private function isPasswordHash(string $value): bool
    {
        return password_get_info($value)['algo'] !== null;
    }

}
