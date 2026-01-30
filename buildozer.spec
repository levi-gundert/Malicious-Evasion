# Buildozer spec file for Android APK
# Build with: buildozer android debug

[app]

# Title of your application
title = Evasion Artifact Placer

# Package name (Java-style)
package.name = evasionplacer

# Package domain (for android.package)
package.domain = com.evasion

# Source code location
source.dir = .

# Source files to include
source.include_exts = py,png,jpg,kv,atlas,json,yaml

# Source directories to include
source.include_patterns = gui/*,extractor/*,assets/*

# Application entry point
main.py = gui/main.py

# Application versioning
version = 1.0.0

# Requirements (Python packages to include)
requirements = python3,kivy,plyer,requests,pyyaml

# Android SDK/NDK settings
android.api = 31
android.minapi = 21
android.ndk = 25b

# Android permissions
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# Orientation
orientation = portrait

# Fullscreen mode
fullscreen = 0

# Android arch to build for
android.archs = arm64-v8a, armeabi-v7a

# Android features
android.features = android.hardware.touchscreen

# Icon (path to 512x512 PNG)
# icon.filename = %(source.dir)s/assets/icon.png

# Presplash (loading screen)
# presplash.filename = %(source.dir)s/assets/presplash.png

# Presplash color
presplash.color = #1a1a2e

# Whether to include Python 3 stdlib
android.include_exts = py,kv,atlas,json

# Log level
log_level = 2

# Show warnings
warn_on_root = 1


[buildozer]

# Log level (0 = error only, 1 = info, 2 = debug)
log_level = 2

# Path to build output
build_dir = ./.buildozer

# Path to platform-specific directories
android.sdk_path = 
android.ndk_path = 
android.ant_path = 

# Path to jarsigner and zipalign
android.jarsigner_path = 


# iOS settings (for future use)
[ios]
# iOS-specific settings would go here
