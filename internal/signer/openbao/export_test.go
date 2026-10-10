// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package openbao

import "time"

// ExpireReauthThrottleForTest backdates tm's last login attempt to beyond
// minReauthInterval, so the next Reauth is allowed to log in.
//
// In an _test.go file so it is compiled only for tests and never becomes part
// of the package's API. Every TokenManager has just logged in when its
// constructor returns, so without this a spec of the request-path re-login
// would have to wait the whole interval out.
func ExpireReauthThrottleForTest(tm *TokenManager) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.lastLogin = time.Now().Add(-minReauthInterval - time.Second)
}
