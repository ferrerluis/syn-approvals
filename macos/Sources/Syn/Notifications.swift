import Foundation
import UserNotifications

final class SynNotificationCenter: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let category = "SYN_APPROVAL"
    static let reviewAction = "SYN_REVIEW"
    static let denyAction = "SYN_DENY"

    var onReview: (@Sendable (String) -> Void)?
    var onDeny: (@Sendable (String) -> Void)?

    func configure() async throws {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let category = UNNotificationCategory(
            identifier: Self.category,
            actions: [
                UNNotificationAction(identifier: Self.reviewAction, title: "Review", options: [.foreground]),
                UNNotificationAction(identifier: Self.denyAction, title: "Deny", options: [.destructive]),
            ],
            intentIdentifiers: [],
            options: []
        )
        center.setNotificationCategories([category])
        _ = try await center.requestAuthorization(options: [.alert, .sound])
    }

    func post(request: VerifiedApprovalRequest, targetName: String) async throws {
        let content = UNMutableNotificationContent()
        content.title = "Syn approval requested"
        content.body = "\(targetName) · \(request.invokingUser) · just now"
        content.categoryIdentifier = Self.category
        content.userInfo = ["requestID": request.id]
        content.sound = .default
        try await UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: "syn-\(request.id)", content: content, trigger: nil)
        )
    }

    func remove(requestID: String) {
        let identifier = "syn-\(requestID)"
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [identifier])
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [identifier])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions { [.banner, .sound] }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        guard let requestID = response.notification.request.content.userInfo["requestID"] as? String else { return }
        if response.actionIdentifier == Self.denyAction { onDeny?(requestID) }
        else { onReview?(requestID) }
    }
}
