import { ApiError, id, object, page, request, text, type Organization, type Role } from './api'
import type { Page } from './targets-api'

export interface ManagedUser {
  id: string; username: string; display_name: string; status: 'active' | 'disabled'; system_admin: boolean
  must_change_password: boolean; version: number; created_at?: string; updated_at?: string
}
export interface ManagedOrganization extends Organization {
  timezone: string; version: number; full_response_retention_days: number; created_at?: string; updated_at?: string
}
export interface Member {
  id: string; org_id: string; user_id: string; username: string; roles: string[]; permissions: string[]
  status: 'active' | 'disabled'; version: number; created_at?: string; updated_at?: string
}
export interface UserCreate { username: string; display_name: string; password: string }
export interface UserPatch { version: number; display_name: string; status: 'active' | 'disabled' }
export interface OrganizationCreate { name: string; timezone: string }
export interface OrganizationPatch extends OrganizationCreate { version: number; status: 'active' | 'disabled'; full_response_retention_days: number }
export interface MemberCreate { user_id: string; roles: string[]; permissions: string[] }
export interface MemberPatch { version: number; roles: string[]; permissions: string[]; status: 'active' | 'disabled' }

function version(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 2147483647 }
function status(value: unknown) { return value === 'active' || value === 'disabled' }
function string(value: unknown, max: number): value is string { return typeof value === 'string' && [...value].length <= max && !/\p{Cc}/u.test(value) }
function uniqueStrings(value: unknown, max: number): value is string[] { return Array.isArray(value) && value.length <= max && value.every((item) => text(item, 128)) && new Set(value).size === value.length }
function safeRead(value: unknown, allowed: string[]): value is Record<string, unknown> {
  return object(value) && Object.keys(value).every((key) => allowed.includes(key)) && ['created_at', 'updated_at'].every((key) => value[key] === undefined || (text(value[key], 64) && Number.isFinite(Date.parse(value[key]))))
}
export function managedUser(value: unknown): value is ManagedUser {
  return safeRead(value, ['id', 'username', 'display_name', 'status', 'system_admin', 'must_change_password', 'version', 'created_at', 'updated_at']) && id(value.id) &&
    text(value.username, 64) && string(value.display_name, 128) && status(value.status) && typeof value.system_admin === 'boolean' && typeof value.must_change_password === 'boolean' && version(value.version)
}
export function managedOrganization(value: unknown): value is ManagedOrganization {
  return safeRead(value, ['id', 'name', 'timezone', 'status', 'full_response_retention_days', 'version', 'created_at', 'updated_at']) && id(value.id) &&
    text(value.name, 128) && text(value.timezone, 64) && status(value.status) && version(value.version) && typeof value.full_response_retention_days === 'number' &&
    Number.isInteger(value.full_response_retention_days) && value.full_response_retention_days >= 0 && value.full_response_retention_days <= 180
}
export function member(value: unknown): value is Member {
  return safeRead(value, ['id', 'org_id', 'user_id', 'username', 'roles', 'permissions', 'status', 'version', 'created_at', 'updated_at']) &&
    id(value.id) && id(value.org_id) && id(value.user_id) && text(value.username, 64) && status(value.status) && version(value.version) && uniqueStrings(value.roles, 5) && uniqueStrings(value.permissions, 100)
}
function role(value: unknown): value is Role { return object(value) && text(value.name, 64) && uniqueStrings(value.permissions, 1000) }
function pathID(value: string) { if (!id(value)) throw new ApiError('MI_INVALID_REQUEST'); return value }
function scope(org: string, csrf?: string) { return { 'X-Organization-ID': pathID(org), ...writeHeaders(csrf) } }
function writeHeaders(csrf?: string): Record<string, string> { return csrf ? { 'X-CSRF-Token': csrf } : {} }
function sameUser(userID: string) { return (value: unknown): value is ManagedUser => managedUser(value) && value.id === userID }
function query(cursor = '', q = '') {
  const parameters = new URLSearchParams({ limit: '25' })
  if (cursor) parameters.set('cursor', cursor)
  if (q) parameters.set('q', q)
  return `?${parameters}`
}
export const managementApi = {
  users: (cursor = '', q = '', signal?: AbortSignal): Promise<Page<ManagedUser>> => request(`/users${query(cursor, q)}`, page(managedUser), { signal }),
  createUser: (csrf: string, body: UserCreate, signal?: AbortSignal) => request('/users', managedUser, { body, headers: writeHeaders(csrf), signal }),
  updateUser: (csrf: string, userID: string, body: UserPatch, signal?: AbortSignal) => request(`/users/${pathID(userID)}`, sameUser(userID), { method: 'PATCH', body, headers: writeHeaders(csrf), signal }),
  unlockUser: (csrf: string, userID: string, expectedVersion: number, signal?: AbortSignal) => request(`/users/${pathID(userID)}/unlock`, sameUser(userID), { body: { version: expectedVersion }, headers: writeHeaders(csrf), signal }),
  resetPassword: (csrf: string, userID: string, expectedVersion: number, password: string, signal?: AbortSignal) => request(`/users/${pathID(userID)}/reset-password`, sameUser(userID), { body: { version: expectedVersion, password }, headers: writeHeaders(csrf), signal }),
  organizations: (cursor = '', q = '', signal?: AbortSignal): Promise<Page<ManagedOrganization>> => request(`/organizations${query(cursor, q)}`, page(managedOrganization), { signal }),
  organization: (org: string, signal?: AbortSignal) => request(`/organizations/${pathID(org)}`, (value): value is ManagedOrganization => managedOrganization(value) && value.id === org, { headers: scope(org), signal }),
  createOrganization: (csrf: string, body: OrganizationCreate, signal?: AbortSignal) => request('/organizations', managedOrganization, { body, headers: writeHeaders(csrf), signal }),
  updateOrganization: (csrf: string, org: string, body: OrganizationPatch, signal?: AbortSignal) => request(`/organizations/${pathID(org)}`, (value): value is ManagedOrganization => managedOrganization(value) && value.id === org, { method: 'PATCH', body, headers: scope(org, csrf), signal }),
  members: (org: string, cursor = '', q = '', signal?: AbortSignal): Promise<Page<Member>> => request(`/organizations/${pathID(org)}/members${query(cursor, q)}`, page((value): value is Member => member(value) && value.org_id === org), { headers: scope(org), signal }),
  addMember: (csrf: string, org: string, body: MemberCreate, signal?: AbortSignal) => request(`/organizations/${pathID(org)}/members`, (value): value is Member => member(value) && value.org_id === org, { body, headers: scope(org, csrf), signal }),
  updateMember: (csrf: string, org: string, memberID: string, body: MemberPatch, signal?: AbortSignal) => request(`/organizations/${pathID(org)}/members/${pathID(memberID)}`, (value): value is Member => member(value) && value.org_id === org && value.id === memberID, { method: 'PATCH', body, headers: scope(org, csrf), signal }),
  roles: (org: string, cursor = '', signal?: AbortSignal): Promise<Page<Role>> => request(`/roles${query(cursor)}`, page(role), { headers: scope(org), signal }),
}
