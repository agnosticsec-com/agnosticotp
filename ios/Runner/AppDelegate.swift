import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  // iOS has no FLAG_SECURE equivalent. To stop the app-switcher snapshot from
  // capturing live codes (threat model M2), cover the window with a blur view
  // the moment the app resigns active, and remove it on re-activation. Pairs
  // with the Flutter-side lock-on-inactive that already clears secrets.
  private var privacyView: UIView?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }

  override func applicationWillResignActive(_ application: UIApplication) {
    guard privacyView == nil, let window = window else { return }
    let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemMaterial))
    blur.frame = window.bounds
    blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(blur)
    privacyView = blur
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    privacyView?.removeFromSuperview()
    privacyView = nil
  }
}
