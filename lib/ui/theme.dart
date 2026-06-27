// AgnosticOTP — brand theme.
//
// Colours are the canonical Agnostic Security palette
// (Marketing/Brand Pack/03_Colour/AS_Colours.txt). Do not substitute ad-hoc
// hex; these are the brand spec.

import 'package:flutter/material.dart';

class BrandColors {
  BrandColors._();

  static const Color agnosticBlue = Color(0xFF1F5F8E); // Primary
  static const Color agnosticOrange = Color(0xFFEC6B2D); // Accent
  static const Color ink = Color(0xFF1A1F2B); // Text
  static const Color slate = Color(0xFF6B7280); // Secondary
  static const Color mist = Color(0xFFF7F9FC); // Surface
  static const Color hairline = Color(0xFFE5E7EB); // Divider
}

class AppTheme {
  AppTheme._();

  static const String logoPrimary = 'assets/brand/AS_Logo_Primary.png';
  static const String logoReversed = 'assets/brand/AS_Logo_Reversed_White.png';

  static ThemeData light() {
    const scheme = ColorScheme(
      brightness: Brightness.light,
      primary: BrandColors.agnosticBlue,
      onPrimary: Colors.white,
      secondary: BrandColors.agnosticOrange,
      onSecondary: Colors.white,
      tertiary: BrandColors.agnosticOrange,
      onTertiary: Colors.white,
      surface: BrandColors.mist,
      onSurface: BrandColors.ink,
      surfaceContainerHighest: BrandColors.hairline,
      outline: BrandColors.slate,
      outlineVariant: BrandColors.hairline,
      error: Color(0xFFB3261E),
      onError: Colors.white,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: BrandColors.mist,
      appBarTheme: const AppBarTheme(
        backgroundColor: BrandColors.agnosticBlue,
        foregroundColor: Colors.white,
        centerTitle: false,
      ),
      dividerColor: BrandColors.hairline,
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: BrandColors.agnosticBlue,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8)),
        ),
      ),
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: BrandColors.agnosticOrange,
        foregroundColor: Colors.white,
      ),
    );
  }
}
