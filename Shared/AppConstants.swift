/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import UIKit

public struct AppConstants {

    public static let FxAiOSClientId = "1b1a3e44c54fbb58"

    ///  Enables/disables push notificatuibs for FxA
    public static let MOZ_FXA_PUSH: Bool = {
        #if MOZ_CHANNEL_RELEASE
            return false
        #elseif MOZ_CHANNEL_BETA
            return false
        #elseif MOZ_CHANNEL_NIGHTLY
            return false
        #elseif MOZ_CHANNEL_FENNEC
            return true
        #elseif MOZ_CHANNEL_AURORA
            return true
        #else
            return true
        #endif
    }()
}
