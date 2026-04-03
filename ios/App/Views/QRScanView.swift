// QRScanView.swift — Camera QR code scanner using AVFoundation

import SwiftUI
import AVFoundation

/// Full-screen QR scanner sheet.
/// Calls `onResult` with the decoded string and dismisses itself.
struct QRScanView: View {

    let onResult: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                CameraPreviewView(onResult: { code in
                    onResult(code)
                })
                .ignoresSafeArea()

                // Viewfinder overlay
                VStack {
                    Spacer()
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(.white, lineWidth: 3)
                        .frame(width: 250, height: 250)
                        .shadow(color: .black.opacity(0.5), radius: 8)
                    Text("Point at a CavadVPN QR code")
                        .font(.subheadline)
                        .foregroundStyle(.white)
                        .padding(.top, 16)
                        .shadow(radius: 4)
                    Spacer()
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .foregroundStyle(.white)
                }
            }
        }
    }
}

// MARK: - Camera preview using AVFoundation + UIViewRepresentable

private struct CameraPreviewView: UIViewRepresentable {

    let onResult: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onResult: onResult) }

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        let session = AVCaptureSession()

        // Request camera access
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            context.coordinator.startSession(session, previewView: view)
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                if granted {
                    DispatchQueue.main.async {
                        context.coordinator.startSession(session, previewView: view)
                    }
                }
            }
        default:
            break
        }

        context.coordinator.session = session
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {}

    func dismantleUIView(_ uiView: UIView, coordinator: Coordinator) {
        coordinator.session?.stopRunning()
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {

        var session: AVCaptureSession?
        private var previewLayer: AVCaptureVideoPreviewLayer?
        private let onResult: (String) -> Void
        private var didScan = false

        init(onResult: @escaping (String) -> Void) {
            self.onResult = onResult
        }

        func startSession(_ session: AVCaptureSession, previewView: UIView) {
            guard let device = AVCaptureDevice.default(for: .video),
                  let input  = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input)
            else { return }

            session.addInput(input)

            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]

            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            layer.frame = previewView.bounds
            previewView.layer.addSublayer(layer)
            previewLayer = layer

            DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput objects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            guard !didScan,
                  let obj  = objects.first as? AVMetadataMachineReadableCodeObject,
                  let code = obj.stringValue
            else { return }

            didScan = true
            session?.stopRunning()
            onResult(code)
        }
    }
}

#Preview {
    QRScanView { _ in }
}
