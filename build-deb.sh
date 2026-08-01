#!/bin/bash
# build-deb.sh — Build .deb package for Job Scam Detector v3.0

PACKAGE_NAME="job-scam-detector"
VERSION="3.0.0"
BUILD_DIR="/tmp/${PACKAGE_NAME}-build"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "Building ${PACKAGE_NAME} v${VERSION}..."
echo "============================================================"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/share/${PACKAGE_NAME}"

# Copy files
cp "$SCRIPT_DIR"/*.py "$BUILD_DIR/usr/share/${PACKAGE_NAME}/"
cp "$SCRIPT_DIR"/*.md "$BUILD_DIR/usr/share/${PACKAGE_NAME}/"
cp "$SCRIPT_DIR"/LICENSE "$BUILD_DIR/usr/share/${PACKAGE_NAME}/"
cp "$SCRIPT_DIR"/requirements.txt "$BUILD_DIR/usr/share/${PACKAGE_NAME}/"

# Set permissions
find "$BUILD_DIR/usr/share/${PACKAGE_NAME}" -name "*.py" -exec chmod 644 {} \;
chmod +x "$BUILD_DIR/usr/share/${PACKAGE_NAME}"/*.py

# Create control file
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utility
Priority: optional
Architecture: all
Maintainer: Dave Wells
Description: Job Scam Detector - Automated email forensics for recruitment scam detection
 Features: GUI and CLI interface, batch analysis, HTML reports, reply drafts
 Spam detection, phishing awareness, recruiter verification
 Depends: python3, python3-customtkinter
EOF

# Create postinst script
cat > "$BUILD_DIR/DEBIAN/postinst" <<EOF
#!/bin/bash
ln -sf /usr/share/${PACKAGE_NAME}/scam-detector-gui.py /usr/local/bin/scam-detector
ln -sf /usr/share/${PACKAGE_NAME}/scam_detector_cli.py /usr/local/bin/scam-detector-cli
chmod +x /usr/local/bin/scam-detector
chmod +x /usr/local/bin/scam-detector-cli
echo "Installation complete!"
echo "Run 'scam-detector' for GUI or 'scam-detector-cli --help' for CLI"
EOF

# Create prerm script
cat > "$BUILD_DIR/DEBIAN/prerm" <<EOF
#!/bin/bash
rm -f /usr/local/bin/scam-detector
rm -f /usr/local/bin/scam-detector-cli
EOF

# Fix permissions for dpkg-deb (must be >=0555 and <=0775)
chmod 0755 "$BUILD_DIR/DEBIAN"
chmod 0555 "$BUILD_DIR/DEBIAN/postinst"
chmod 0555 "$BUILD_DIR/DEBIAN/prerm"

# Build .deb package
dpkg-deb --build "$BUILD_DIR" "${SCRIPT_DIR}/${PACKAGE_NAME}_${VERSION}_all.deb"

# Check if build actually succeeded
if [ $? -ne 0 ]; then
    echo "============================================================"
    echo "ERROR: Package build failed!"
    echo "============================================================"
    rm -f "${SCRIPT_DIR}/${PACKAGE_NAME}_${VERSION}_all.deb"
    exit 1
fi

# Cleanup
rm -rf "$BUILD_DIR"

echo "============================================================"
echo "Package built successfully!"
echo "Location: ${SCRIPT_DIR}/${PACKAGE_NAME}_${VERSION}_all.deb"
echo "============================================================"
echo ""
echo "To install: sudo dpkg -i ${PACKAGE_NAME}_${VERSION}_all.deb"
echo "To launch: scam-detector"
