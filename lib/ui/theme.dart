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

  // Dark surfaces derived from the brand Ink colour.
  static const Color _darkScaffold = Color(0xFF12161E);
  static const Color _darkSurface = Color(0xFF1A1F2B); // brand Ink
  static const Color _darkSurfaceHi = Color(0xFF252C3A);
  static const Color _darkOnSurface = Color(0xFFE6EAF0);
  // Agnostic Blue lightened for legibility on dark (keeps the brand hue).
  static const Color _blueOnDark = Color(0xFF4F9BD0);

  static ThemeData dark() {
    const scheme = ColorScheme(
      brightness: Brightness.dark,
      primary: _blueOnDark,
      onPrimary: Color(0xFF08131D),
      secondary: BrandColors.agnosticOrange,
      onSecondary: Colors.white,
      tertiary: BrandColors.agnosticOrange,
      onTertiary: Colors.white,
      surface: _darkSurface,
      onSurface: _darkOnSurface,
      surfaceContainerHighest: _darkSurfaceHi,
      outline: BrandColors.slate,
      outlineVariant: Color(0xFF2A3140),
      error: Color(0xFFEF5350),
      onError: Colors.white,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: _darkScaffold,
      appBarTheme: const AppBarTheme(
        backgroundColor: _darkSurface,
        foregroundColor: _darkOnSurface,
        centerTitle: false,
      ),
      dividerColor: const Color(0xFF2A3140),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: _blueOnDark,
          foregroundColor: const Color(0xFF08131D),
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
        backgroundColor: BrandColors.mist, // neutral so the colour wordmark reads
        foregroundColor: BrandColors.ink,
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
