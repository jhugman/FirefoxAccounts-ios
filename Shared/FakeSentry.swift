/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation

open class Sentry {
    public static let shared = Sentry()

    public func send(message: String, tag: SentryTag = .general, severity: SentrySeverity = .info, extra: [String: Any]? = nil, description: String? = nil, completion: SentryRequestFinished? = nil) {}

    public func sendWithStacktrace(message: String, tag: SentryTag = .general, severity: SentrySeverity = .info, extra: [String: Any]? = nil, description: String? = nil, completion: SentryRequestFinished? = nil) {}

    public func addAttributes(_ attributes: [String: Any]) {}
}

public enum SentryTag: String {
    case swiftData = "SwiftData"
    case browserDB = "BrowserDB"
    case notificationService = "NotificationService"
    case unifiedTelemetry = "UnifiedTelemetry"
    case general = "General"
}

public typealias SentryRequestFinished = (NSError?) -> ()

public enum SentrySeverity: Int {
    case fatal
    case error
    case warning
    case info
    case debug
}
