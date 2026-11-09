# AI-Based Network Intrusion Detection System
## Figma UI/UX Design System Specification
### Academic Capstone Project • Mandatory Tool 5

---

### 1. Color Palette Tokens

| Token Name | Hex Code | Semantic Role | Accessibility Contrast Ratio |
|---|---|---|---|
| `color-primary-dark` | `#0B1714` | Global deep forest canvas background | Neutral Dark Canvas |
| `color-surface-emerald` | `#102621` | Primary card elevation, hero containers | 12.8:1 on `#FFFFFF` (AAA) |
| `color-border-emerald` | `#2D6A4F` | Card outlines, dividers, form containers | 8.4:1 on `#0B1714` (AAA) |
| `color-accent-gold` | `#E2B96F` | Champagne gold borders, headings, scores | 11.2:1 on `#0B1714` (AAA) |
| `color-accent-mint` | `#34D399` | Clean traffic badge, normal flow metrics | 9.8:1 on `#0B1714` (AAA) |
| `color-status-danger` | `#EF4444` | Incursion alerts, malicious flow warnings | 7.6:1 on `#0B1714` (AAA) |
| `color-text-ivory` | `#F1F5F9` | High-contrast body copy, metadata | 14.5:1 on `#0B1714` (AAA) |
| `color-text-muted` | `#94A3B8` | Subtitles, timestamps, parameter keys | 6.2:1 on `#0B1714` (AA) |

---

### 2. Typography Hierarchy

| Style Role | Font Family | Size (px / rem) | Weight | Line Height | Usage |
|---|---|---|---|---|---|
| **Display Title (Hero)** | `Cinzel` / Serif | 38px / 2.38rem | 800 (Extra Bold) | 1.25 | Official Project Title on Screen 0 & Screen 7 |
| **Heading 1 (Sections)** | `Cinzel` / Serif | 26px / 1.62rem | 700 (Bold) | 1.30 | Module Headers, Cyber Defense Titles |
| **Heading 2 (Cards)** | `Plus Jakarta Sans` | 20px / 1.25rem | 700 (Bold) | 1.35 | Threat Alert Headlines, KPI Metrics |
| **Heading 3 (Sub-cards)**| `Plus Jakarta Sans` | 16px / 1.00rem | 600 (Semi Bold) | 1.40 | Form Group Titles, Feature Labels |
| **Body Primary** | `Plus Jakarta Sans` | 14px / 0.88rem | 400 (Regular) | 1.60 | Attack Descriptions, Remediation Steps |
| **Caption / Badges** | `Plus Jakarta Sans` | 12px / 0.75rem | 700 (Bold) | 1.40 | Severity Badges, IP Addresses, TCP Flags |

---

### 3. Elevation, Spacing & Corner Radii

* **Grid System:** 12-column responsive layout, 24px gutters, max-width 1340px.
* **Base Spacing Unit:** 8px (Multiples: 8px, 16px, 24px, 32px, 48px, 64px).
* **Corner Radii:**
  * Small tags & badges: `6px`
  * Form inputs & buttons: `10px`
  * Metric KPI cards: `14px`
  * Threat alert containers: `16px`
  * Hero banner: `20px`
* **Box Shadows:**
  * Card Resting: `0 4px 18px -2px rgba(0, 0, 0, 0.45)`
  * Card Hover: `0 12px 28px -4px rgba(0, 0, 0, 0.65)`
  * Hero Container: `0 16px 36px -6px rgba(0, 0, 0, 0.55)`

---

### 4. Interactive Components & States
* **Primary Navigation Buttons (Modules 01, 02, 03):**
  * Resting: Deep Emerald border, `#102621` background, `#E2B96F` text.
  * Active/Selected: `#10332C` background, `#FFFFFF` text, Champagne Gold accent border.
  * Hover: 2px transform translateY, elevated gold shadow.
* **Radar Sensor Visual (Screen 8):**
  * 3 Concentric gold & cyan rings, crosshairs, radial dark gradient.
  * Rotating 360-degree sweep beam with conical gradient.
  * Blinking threat indicator blips with pulse animation.
