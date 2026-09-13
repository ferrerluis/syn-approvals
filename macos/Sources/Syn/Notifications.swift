import Foundation
import UserNotifications

protocol SynNotifying: AnyObject, Sendable {
    var onReview: (@Sendable (String) -> Void)? { get set }
    var onDeny: (@Sendable (String) -> Void)? { get set }
    func configure() async throws
    func post(request: VerifiedApprovalRequest, targetName: String) async throws
    func remove(requestID: String)
}

final class SynNotificationCenter: NSObject, SynNotifying, UNUserNotificationCenterDelegate, @unchecked Sendable {
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
        guard try await center.requestAuthorization(options: [.alert, .sound]) else {
            throw SynProtocolError.invalid("Enable Syn notifications in System Settings to receive approval alerts")
        }
    }

    func post(request: VerifiedApprovalRequest, targetName: String) async throws {
        let content = Self.content(request: request, targetName: targetName)
        try await UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: "syn-\(request.id)", content: content, trigger: nil)
        )
    }

    static func content(request: VerifiedApprovalRequest, targetName: String) -> UNMutableNotificationContent {
        let content = UNMutableNotificationContent()
        content.title = "Syn approval requested"
        content.body = "\(SafeDisplay.render(Data(targetName.utf8))) · \(SafeDisplay.render(Data(request.invokingUser.utf8))) · just now"
        content.categoryIdentifier = Self.category
        content.userInfo = ["requestID": request.id]
        content.sound = .default
        return content
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
