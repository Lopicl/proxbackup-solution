// SPDX-License-Identifier: AGPL-3.0-or-later

// What the signed-in user may do, for hiding actions. The console checks
// every request itself; this only keeps the UI from offering what would fail.

import { createContext, useContext } from 'react'
import type { Me, Perm } from './api'

export const MeContext = createContext<Me | null>(null)

/** A client as far as permissions go; tags undefined = unknown (e.g. a run's client). */
type ClientRef = { id: number; tags?: string[] }

/**
 * Whether the user has perm: for client, or without one for at least some
 * clients. Console permissions (PBS servers, settings, users) are only ever
 * granted for all clients.
 */
export function can(me: Me | null, perm: Perm, client?: ClientRef): boolean {
  const sc = me?.permissions[perm]
  if (!sc) return false
  if (!client || sc.all || sc.clients.includes(client.id)) return true
  if (client.tags === undefined) return sc.tags.length > 0 // can't tell: let the console decide
  return client.tags.some((t) => sc.tags.includes(t))
}

/** Whether the user has perm for all clients. */
export function canAll(me: Me | null, perm: Perm): boolean {
  return !!me?.permissions[perm]?.all
}

/** Permission checks for the signed-in user. */
export function usePerms() {
  const me = useContext(MeContext)
  return {
    me,
    can: (perm: Perm, client?: ClientRef) => can(me, perm, client),
    all: (perm: Perm) => canAll(me, perm),
  }
}
