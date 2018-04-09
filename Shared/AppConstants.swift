/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import UIKit

public enum AppBuildChannel: String {
    case release = "release"
    case beta = "beta"
    case developer = "developer"
}

public struct AppConstants {

    /// Build Channel.
    public static let BuildChannel: AppBuildChannel = {
        #if MOZ_CHANNEL_RELEASE
        return AppBuildChannel.release
        #elseif MOZ_CHANNEL_BETA
        return AppBuildChannel.beta
        #elseif MOZ_CHANNEL_FENNEC
        return AppBuildChannel.developer
        #else
        return AppBuildChannel.developer
        #endif
    }()

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
            return false
        #elseif MOZ_CHANNEL_AURORA
            return false
        #else
            return false
        #endif
    }()

    public static let scheme: String = {
        guard let identifier = Bundle.main.bundleIdentifier else {
            return "unknown"
        }
        return identifier.replacingOccurrences(of: "org.mozilla.ios.", with: "")
    }()

    public static let PrefSendUsageData = "pref.sendUsageData"
}
