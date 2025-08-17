# FastHTML CSS Utilities Guide for Claude Code

## Quick Reference for `cjm-fasthtml-daisyui` and `cjm-fasthtml-tailwind`

This guide provides essential information for using the `cjm-fasthtml-daisyui` (DaisyUI v5) and `cjm-fasthtml-tailwind` (Tailwind CSS v4) libraries in FastHTML projects.

## Overview

### `cjm-fasthtml-daisyui`
- **Purpose**: Python-native DaisyUI v5 component class builders
- **Components**: Buttons, cards, modals, dropdowns, forms, navigation, etc.
- **Syntax**: Factory objects that generate CSS classes (e.g., `btn`, `btn_colors.primary`)
- **FastHTML Examples**: Every module includes `_fasthtml` examples showing real usage
- **Combined Usage**: Many DaisyUI FastHTML examples also demonstrate Tailwind utility integration

### `cjm-fasthtml-tailwind`
- **Purpose**: Python-native Tailwind CSS v4 utility class builders  
- **Utilities**: Spacing, layout, typography, colors, effects, etc.
- **Syntax**: Factory functions that generate CSS classes (e.g., `p(4)`, `m.x(2)`)
- **FastHTML Examples**: Modules include `fasthtml` examples demonstrating integration

### Design Philosophy
- **Foundational Libraries**: These provide type-safe building blocks for CSS classes
- **Composability**: Designed to enable creation of higher-level component libraries
- **Not Opinionated**: Intentionally provides utilities, not pre-built components
- **Your Components**: Build your own component libraries on top of these foundations

## Essential CLI Commands

### Critical Workflow Commands

```bash
# ALWAYS TEST CODE BEFORE USING (MANDATORY)
cjm-daisyui-explore test-code "<code>"
cjm-tailwind-explore test-code "<code>"

# Get correct imports
cjm-daisyui-explore imports
cjm-tailwind-explore imports

# Search for functionality
cjm-daisyui-explore search <query>
cjm-tailwind-explore search <query>

# IMPORTANT: View FastHTML-specific examples for any module
cjm-daisyui-explore examples -m <module>  # Lists all examples including FastHTML ones
cjm-tailwind-explore examples -m <module>  # Most end with '_fasthtml'
```

### Discovery Commands

```bash
# List available modules
cjm-daisyui-explore modules
cjm-tailwind-explore modules

# List factories in a module
cjm-daisyui-explore factories -m <module>
cjm-tailwind-explore factories -m <module>

# Get factory details
cjm-daisyui-explore factory <module> <name>
cjm-tailwind-explore factory <module> <name>

# View examples
cjm-daisyui-explore examples -m <module>
cjm-tailwind-explore examples -m <module>

# View specific example source
cjm-daisyui-explore example <module> <name>
cjm-tailwind-explore example <module> <name>

# Scan existing code for migration opportunities
cjm-daisyui-explore scan <file>
cjm-tailwind-explore scan <file>
```

## Common Import Patterns

### FastHTML Elements
```python
from fasthtml.common import *
# This imports all standard HTML elements as Python functions:
# Div, Span, Button, Input, Form, Label, Select, Option, 
# A, P, H1-H6, Ul, Li, Table, Tr, Td, etc.
# Plus special semantic elements like Card (→ <article>), Figure (→ <figure>)
```

### DaisyUI Components
```python
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_colors, btn_sizes, btn_modifiers
from cjm_fasthtml_daisyui.components.data_display.card import card, card_body, card_title, card_actions
from cjm_fasthtml_daisyui.components.actions.modal import modal, modal_box, modal_action
from cjm_fasthtml_daisyui.components.navigation.navbar import navbar, navbar_start, navbar_center, navbar_end
from cjm_fasthtml_daisyui.components.data_input.text_input import text_input, text_input_colors
from cjm_fasthtml_daisyui.core.resources import get_daisyui_headers
from cjm_fasthtml_tailwind.core.base import combine_classes
```

### Tailwind Utilities
```python
from cjm_fasthtml_tailwind.utilities.spacing import p, m, space
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import flex_display, gap, grid_cols, items, justify
from cjm_fasthtml_tailwind.utilities.sizing import w, h, max_w, min_h
from cjm_fasthtml_tailwind.utilities.typography import text_color, font_size, font_weight
from cjm_fasthtml_tailwind.utilities.backgrounds import bg
from cjm_fasthtml_tailwind.utilities.borders import border, rounded
from cjm_fasthtml_tailwind.core.base import combine_classes
```

## Usage Patterns

### Basic DaisyUI Component
```python
from fasthtml.common import Button, Card, Div
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_colors, btn_sizes
from cjm_fasthtml_daisyui.components.data_display.card import card, card_body, card_actions
from cjm_fasthtml_tailwind.core.base import combine_classes

# Button with color and size
button_classes = combine_classes(btn, btn_colors.primary, btn_sizes.lg)
Button("Click me", cls=button_classes)

# Card with body (Card creates <article> element)
Card(
    Div("Card content", cls=str(card_body)),
    Div(
        Button("Action", cls=str(btn)),
        cls=str(card_actions)
    ),
    cls=str(card)
)
```

### Basic Tailwind Utilities
```python
from fasthtml.common import Div, P
from cjm_fasthtml_tailwind.utilities.spacing import p, m
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import flex_display, gap
from cjm_fasthtml_tailwind.utilities.typography import font_size, font_weight
from cjm_fasthtml_daisyui.utilities.semantic_colors import text_dui
from cjm_fasthtml_tailwind.core.base import combine_classes

# Spacing and layout
div_classes = combine_classes(p(4), m.x(2), flex_display, gap(4))
Div("Content", cls=div_classes)

# Typography with semantic colors (theme-aware)
text_classes = combine_classes(
    text_dui.primary,  # Uses theme's primary color
    font_size.lg,
    font_weight.bold
)
P("Styled text", cls=text_classes)
```

### Combining Both Libraries
```python
from fasthtml.common import Button
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_colors
from cjm_fasthtml_tailwind.utilities.spacing import m
from cjm_fasthtml_tailwind.utilities.sizing import w
from cjm_fasthtml_tailwind.core.base import combine_classes

# DaisyUI component with Tailwind utilities
button_classes = combine_classes(
    btn,                      # DaisyUI base button
    btn_colors.primary,       # DaisyUI button color
    m.y(2),                  # Tailwind margin
    w.full                   # Tailwind width
)
Button("Full width button", cls=button_classes)
```

## Key Module Categories

### DaisyUI Modules (65 total)
- **Actions**: button, dropdown, modal, swap, theme_controller
- **Data Display**: card, badge, table, stat, carousel, chat_bubble, accordion
- **Data Input**: text_input, checkbox, radio, select, toggle, file_input
- **Feedback**: alert, loading, progress, toast, tooltip
- **Layout**: drawer, footer, hero, divider, join
- **Navigation**: navbar, menu, breadcrumbs, pagination, tabs, steps

### Tailwind Modules (15 total)
- **Core**: spacing, sizing, typography, backgrounds, borders
- **Layout**: flexbox_and_grid, layout, effects
- **Interactive**: interactivity, transitions_and_animation
- **Specialized**: accessibility, filters, transforms, svg, tables

## Factory Syntax Reference

### DaisyUI Factories
```python
# Fixed value factories (no input)
btn                  # Returns: "btn"
card                 # Returns: "card"

# Choice factories (specific options)
btn_colors.primary   # Returns: "btn-primary"
btn_sizes.lg        # Returns: "btn-lg"

# Modifiers
btn_modifiers.wide   # Returns: "btn-wide"
btn_modifiers.block  # Returns: "btn-block"
```

### Tailwind Factories
```python
# Scaled factories (numeric input)
p(4)                 # Returns: "p-4"
m(2)                 # Returns: "m-2"
gap(3)               # Returns: "gap-3"

# Directional factories
p.x(4)               # Returns: "px-4"
m.y(2)               # Returns: "my-2"
p.t(3)               # Returns: "pt-3"

# Special values
p.auto               # Returns: "p-auto"
w.full               # Returns: "w-full"
h.screen             # Returns: "h-screen"

# Color utilities (with shade)
bg.blue(500)         # Returns: "bg-blue-500"
text_color.red(600)  # Returns: "text-red-600"
```

## Testing Code Before Implementation

**CRITICAL**: Always test generated code before using it in your project:

```bash
# Test DaisyUI code
cjm-daisyui-explore test-code "from cjm_fasthtml_daisyui.components.actions.button import btn; print(str(btn))"

# Test Tailwind code
cjm-tailwind-explore test-code "from cjm_fasthtml_tailwind.utilities.spacing import p; print(str(p(4)))"

# Test combined code
cjm-daisyui-explore test-code "
from cjm_fasthtml_daisyui.components.actions.button import btn
from cjm_fasthtml_tailwind.utilities.spacing import m
from cjm_fasthtml_tailwind.core.base import combine_classes
print(combine_classes(btn, m(2)))
"
```

## Common Tasks

### Find the Right Component/Utility
```bash
# Search for button-related functionality
cjm-daisyui-explore search button
cjm-tailwind-explore search flex

# Search with source code
cjm-daisyui-explore search modal --include-source
```

### Explore a Specific Module
```bash
# See what's in the button module
cjm-daisyui-explore factories -m actions.button

# Get details on a specific factory
cjm-daisyui-explore factory actions.button btn_colors
```

### Get Working Examples
```bash
# List examples for a module (includes FastHTML examples!)
cjm-daisyui-explore examples -m actions.button
# Output shows: basic, basic_fasthtml, colors_fasthtml, etc.

# View specific FastHTML example code
cjm-daisyui-explore example actions.button basic_fasthtml
# Shows real FastHTML component usage with Button, Div, etc.
# NOTE: Many DaisyUI examples also show Tailwind utilities in use!

# Tailwind also has FastHTML examples
cjm-tailwind-explore example spacing fasthtml
# Shows spacing utilities used with FastHTML components

# Example showing combined usage (from DaisyUI examples):
cjm-daisyui-explore example navigation.menu basic_fasthtml
# Often includes Tailwind utilities like w(56), rounded.box, etc.
```

### Migrate Existing Code
```bash
# Scan file for replaceable CSS patterns
cjm-daisyui-explore scan app.py
cjm-tailwind-explore scan main.py
```

## Headers Setup

For DaisyUI components to work properly, include the necessary headers:

```python
from cjm_fasthtml_daisyui.core.resources import get_daisyui_headers

# In your FastHTML app
app = FastHTML(hdrs=get_daisyui_headers())
```

## Troubleshooting

### Import Errors
- Use the CLI to get correct imports: `cjm-daisyui-explore imports`
- Factories are in specific submodules, not the root package

### Syntax Errors
- DaisyUI: Most factories are properties (e.g., `btn`, `btn_colors.primary`)
- Tailwind: Scaled utilities use function calls (e.g., `p(4)`, not `p[4]`)
- Always use `combine_classes()` to merge multiple classes

### Testing Failed
- Check factory names with `factories` command
- Verify correct module with `search` command
- Look at examples for correct usage patterns

## Quick Decision Tree

1. **Component needed?** (button, card, modal, etc.)
   → Use `cjm-daisyui-explore search <component>`
   → Check FastHTML examples: `cjm-daisyui-explore examples -m <module>`

2. **Utility needed?** (spacing, colors, layout, etc.)
   → Use `cjm-tailwind-explore search <utility>`
   → Check FastHTML examples: `cjm-tailwind-explore examples -m <module>`

3. **Not sure which library?**
   → DaisyUI: Full components (buttons, cards, modals)
   → Tailwind: Individual utilities (padding, margins, colors)

4. **Before implementing:**
   → ALWAYS use `test-code` to validate
   → Get imports with `imports` command
   → Check FastHTML examples with `example <module> <name>_fasthtml`

## Extended Component Reference

### Form Components (DaisyUI)
```python
from fasthtml.common import Input, Select, Option
from cjm_fasthtml_daisyui.components.data_input.text_input import text_input, text_input_colors, text_input_sizes
from cjm_fasthtml_daisyui.components.data_input.select import select, select_colors
from cjm_fasthtml_daisyui.components.data_input.checkbox import checkbox
from cjm_fasthtml_daisyui.components.data_input.toggle import toggle, toggle_colors
from cjm_fasthtml_tailwind.core.base import combine_classes

# Text Input with variants
input_classes = combine_classes(text_input, text_input_colors.primary, text_input_sizes.lg)
Input(type="text", cls=input_classes)

# Select dropdown
Select(Option("Choose..."), cls=combine_classes(select, select_colors.accent))

# Checkbox and Toggle
Input(type="checkbox", cls=str(checkbox))
Input(type="checkbox", cls=combine_classes(toggle, toggle_colors.success))
```

### Navigation Components (DaisyUI)
```python
from fasthtml.common import Div, Ul, Li, A
from cjm_fasthtml_daisyui.components.navigation.menu import menu
from cjm_fasthtml_daisyui.components.navigation.tabs import tabs, tab, tab_modifiers
from cjm_fasthtml_daisyui.components.navigation.breadcrumbs import breadcrumbs
from cjm_fasthtml_daisyui.utilities.semantic_colors import bg_dui
from cjm_fasthtml_tailwind.utilities.borders import rounded
from cjm_fasthtml_tailwind.utilities.sizing import w
from cjm_fasthtml_tailwind.core.base import combine_classes

# Menu
menu_classes = combine_classes(menu, bg_dui.base_200, rounded.box, w(56))
Ul(Li(A("Item 1")), Li(A("Item 2")), cls=menu_classes)

# Tabs
Div(
    A("Tab 1", role="tab", cls=str(tab)),
    A("Tab 2", role="tab", cls=combine_classes(tab, tab_modifiers.active)),
    role="tablist", cls=str(tabs)
)

# Breadcrumbs
Div(Ul(Li(A("Home")), Li(A("Docs")), Li("Current")), cls=str(breadcrumbs))
```

### Feedback Components (DaisyUI)
```python
from fasthtml.common import Div, Button, Span
from cjm_fasthtml_daisyui.components.feedback.alert import alert, alert_colors
from cjm_fasthtml_daisyui.components.feedback.tooltip import tooltip, tooltip_placement
from cjm_fasthtml_daisyui.components.feedback.loading import loading, loading_styles, loading_sizes
from cjm_fasthtml_tailwind.core.base import combine_classes

# Alert with colors
Div("Warning message", role="alert", cls=combine_classes(alert, alert_colors.warning))

# Tooltip
Div(Button("Hover me"), cls=combine_classes(tooltip, tooltip_placement.top), data_tip="Hello!")

# Loading spinner
Span(cls=combine_classes(loading, loading_styles.spinner, loading_sizes.lg))
```

## Semantic Colors vs Fixed Colors

### When to Use DaisyUI Semantic Colors
Use semantic colors when you want elements to adapt to the theme:
```python
from cjm_fasthtml_daisyui.utilities.semantic_colors import bg_dui, text_dui, border_dui

# ✅ Good - Theme-aware colors
Button("Primary Action", cls=combine_classes(
    bg_dui.primary,           # Adapts to theme's primary color
    text_dui.primary_content  # Always readable on primary background
))

# ✅ Good - Layout colors
Div(
    cls=combine_classes(
        bg_dui.base_200,      # Slightly darker than base background
        text_dui.base_content # Main text color for the theme
    )
)

# ✅ Good - Status indicators
Alert("Error!", cls=combine_classes(
    bg_dui.error,
    text_dui.error_content   # Ensures contrast
))
```

### When to Use Tailwind Fixed Colors
Use Tailwind colors for specific design requirements that shouldn't change:
```python
from cjm_fasthtml_tailwind.utilities.typography import text_color
from cjm_fasthtml_tailwind.utilities.backgrounds import bg

# ✅ Good - Brand-specific colors that must stay consistent
Logo(cls=str(text_color.blue(600)))  # Company blue

# ✅ Good - Data visualization with specific color meanings
Span("Increase", cls=str(text_color.green(500)))  # Green = positive
Span("Decrease", cls=str(text_color.red(500)))    # Red = negative

# ❌ Avoid - UI elements should use semantic colors
Button("Click", cls=str(bg.blue(500)))  # Should use bg_dui.primary
```

### Best Practice: Prefer Semantic Colors
For most UI elements, semantic colors provide better user experience:
- They adapt to light/dark themes automatically
- They maintain proper contrast ratios
- They create consistent visual language
- They respect user preferences

## Advanced Patterns

### State Modifiers and Responsive Design
```python
# Both libraries support state and responsive modifiers
# Pattern: factory.state.breakpoint or factory.breakpoint.state

# DaisyUI modifiers
btn.hover                    # hover:btn
btn_colors.primary.focus     # focus:btn-primary
btn.md                       # md:btn
btn.hover.lg                # lg:hover:btn

# Tailwind modifiers
p(4).hover                   # hover:p-4
bg.blue(500).focus          # focus:bg-blue-500
text_color.gray(900).md     # md:text-gray-900
shadow.lg.hover.md          # md:hover:shadow-lg

# Dark mode support
btn.dark                     # dark:btn
bg.gray(800).dark           # dark:bg-gray-800
```

### Color System (Tailwind)
```python
# Full color palette with shades
from cjm_fasthtml_tailwind.utilities.backgrounds import bg
from cjm_fasthtml_tailwind.utilities.typography import text_color
from cjm_fasthtml_tailwind.utilities.borders import border_color

# Standard colors with shades (50-950)
bg.blue(500)                # bg-blue-500
text_color.gray(900)        # text-gray-900
border_color.red(300)       # border-red-300

# With opacity
bg.blue(500).opacity(75)    # bg-blue-500/75
text_color.white.opacity(90) # text-white/90

# Gradients
from cjm_fasthtml_tailwind.utilities.backgrounds import bg_linear, from_color, to_color
gradient_classes = combine_classes(
    bg_linear.to_r,          # bg-gradient-to-r
    from_color.purple(400),  # from-purple-400
    to_color.pink(400)       # to-pink-400
)
```

### Layout Helpers (Tailwind)
```python
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import (
    flex_center, flex_between, grid_center, responsive_grid
)

# Pre-built patterns
flex_center()                # flex justify-center items-center
flex_between()               # flex justify-between items-center
grid_center()                # grid place-items-center
responsive_grid(1, 2, 3)     # grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4

# Custom layouts
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import flex_display, justify, items, gap
custom_flex = combine_classes(flex_display, justify.between, items.start, gap(4))
```

### Effects and Transitions (Tailwind)
```python
from cjm_fasthtml_tailwind.utilities.effects import shadow, ring, ring_color
from cjm_fasthtml_tailwind.utilities.transitions_and_animation import hover_effect, smooth_transition

# Shadows and rings
card_effects = combine_classes(
    shadow.lg,               # shadow-lg
    ring(2).focus,          # focus:ring-2
    ring_color.blue(500).focus  # focus:ring-blue-500
)

# Transitions
button_transition = combine_classes(
    hover_effect(),          # transition-all duration-200 ease-in-out
    scale_tw(95).active     # active:scale-95
)
```

### Semantic Colors (DaisyUI)
```python
from cjm_fasthtml_daisyui.utilities.semantic_colors import bg_dui, text_dui, border_dui

# Theme-aware colors with companion colors for contrast
bg_dui.primary              # bg-primary (background)
text_dui.primary_content    # text-primary-content (text ON primary background)

bg_dui.secondary            # bg-secondary
text_dui.secondary_content  # text-secondary-content (text ON secondary)

bg_dui.accent               # bg-accent
text_dui.accent_content     # text-accent-content (text ON accent)

# Base colors for layouts
bg_dui.base_100             # bg-base-100 (main background)
bg_dui.base_200             # bg-base-200 (slightly darker)
bg_dui.base_300             # bg-base-300 (even darker)
text_dui.base_content       # text-base-content (main text color)

# Status colors with companion colors
bg_dui.info                 # bg-info
text_dui.info_content       # text-info-content (text ON info background)

bg_dui.success              # bg-success
text_dui.success_content    # text-success-content (text ON success)

bg_dui.warning              # bg-warning
text_dui.warning_content    # text-warning-content (text ON warning)

bg_dui.error                # bg-error
text_dui.error_content      # text-error-content (text ON error)

# Example: Button with proper contrast
Button(
    "Click me",
    cls=combine_classes(bg_dui.primary, text_dui.primary_content)
)
# The text will always be visible on the primary background
```

## Refactoring UI Design Principles

### 1. Start with Too Much Whitespace
```python
# Use generous spacing initially, then reduce if needed
container_classes = combine_classes(p(8), space.y(6))  # Start spacious
# Later: combine_classes(p(6), space.y(4))  # Adjust if too much
```

### 2. Establish Visual Hierarchy
```python
from cjm_fasthtml_daisyui.utilities.semantic_colors import text_dui

# Use size, weight, and semantic colors to create hierarchy
heading_classes = combine_classes(
    font_size._2xl,          # Largest size for main heading (text-2xl)
    font_weight.bold,        # Bold weight
    text_dui.base_content    # Main content color (adapts to theme)
)

subheading_classes = combine_classes(
    font_size.lg,            # Smaller than heading
    font_weight.semibold,    # Less weight
    text_dui.base_content.opacity(80)  # Slightly faded
)

body_classes = combine_classes(
    font_size.base,          # Default size
    font_weight.normal,      # Regular weight
    text_dui.base_content.opacity(60)  # More faded for less emphasis
)
```

### 3. Use Color Purposefully
```python
# Primary actions should stand out
primary_button = combine_classes(btn, btn_colors.primary)

# Secondary actions should be subtle
secondary_button = combine_classes(btn, btn_styles.ghost)

# Destructive actions need warning colors
delete_button = combine_classes(btn, btn_colors.error)
```

### 4. Create Depth with Shadows
```python
# Cards and elevated elements need shadows
card_classes = combine_classes(
    card,
    shadow.md,               # Medium shadow for cards
    shadow.xl.hover         # Larger shadow on hover
)

# Modals need stronger shadows
modal_classes = combine_classes(
    modal_box,
    shadow.xl2              # Extra large shadow for modals
)
```

### 5. Use Fewer Borders
```python
# Replace borders with spacing and background colors
# Instead of: border, border_color.gray(300)
section_classes = combine_classes(
    bg_dui.base_200,        # Light background instead of border
    p(6),                   # Padding for breathing room
    rounded.lg              # Rounded corners for softness
)
```

### 6. Think Outside the Box (Literally)
```python
# Don't box everything - use spacing and alignment
# Bad: Everything in boxes with borders
# Good: Strategic use of whitespace and alignment
layout_classes = combine_classes(
    flex_display,
    flex_direction.col,
    gap(8)                  # Space between sections, no boxes needed
)
```

### 7. Emphasize by De-emphasizing
```python
from cjm_fasthtml_daisyui.utilities.semantic_colors import text_dui

# Make important elements stand out by making others subtle
# Important element
cta_button = combine_classes(
    btn,
    btn_colors.primary,
    btn_sizes.lg,
    shadow.lg
)

# Supporting elements - more subtle
helper_text = combine_classes(
    font_size.sm,
    text_dui.base_content.opacity(50)  # Faded for less emphasis
)
```

### 8. Use High-Quality Images
```python
# When using avatars or images, ensure quality
from cjm_fasthtml_daisyui.components.data_display.avatar import avatar
avatar_classes = combine_classes(
    avatar,
    w(24),                  # Large enough to see clearly
    rounded.full            # Circular for modern look
)
```

### 9. Align Everything
```python
# Use consistent alignment with grid or flexbox
grid_layout = combine_classes(
    grid_display,
    grid_cols(12),          # 12-column grid for flexibility
    gap(6),                 # Consistent gaps
    items.start             # Align items consistently
)
```

### 10. Use Good Fonts
```python
# Stick with system fonts or proven web fonts
from cjm_fasthtml_tailwind.utilities.typography import font_family
heading_font = combine_classes(
    font_family.sans,       # Clean sans-serif for headings
    tracking.tight          # Tighter letter spacing for headlines
)

body_font = combine_classes(
    font_family.sans,       # Consistent font family
    leading.relaxed         # Comfortable line height for reading
)
```

## Building Higher-Level Components

These foundational libraries are designed to enable you to build your own component libraries:

```python
from fasthtml.common import Card, Div, Figure, Img, H2, P, Span, Button
from cjm_fasthtml_daisyui.components.data_display.card import card, card_body, card_title, card_actions
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_colors, btn_sizes
from cjm_fasthtml_daisyui.utilities.semantic_colors import bg_dui, text_dui
from cjm_fasthtml_tailwind.utilities.spacing import p
from cjm_fasthtml_tailwind.utilities.typography import font_size, font_weight, line_clamp
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import justify, items
from cjm_fasthtml_tailwind.utilities.effects import shadow
from cjm_fasthtml_tailwind.core.base import combine_classes

# Example: Create your own reusable card component
def ProductCard(title, description, price, image_url=None):
    """Higher-level component built on the foundations."""
    return Card(
        # Image section if provided
        Figure(Img(src=image_url), cls=str(p.x(0))) if image_url else None,
        Div(
            H2(title, cls=combine_classes(
                card_title,
                font_size.xl,
                font_weight.bold
            )),
            P(description, cls=combine_classes(
                text_dui.base_content.opacity(70),  # Semantic color
                line_clamp(3)  # Limit to 3 lines
            )),
            Div(
                Span(f"${price}", cls=combine_classes(
                    font_size._2xl,
                    font_weight.bold,
                    text_dui.primary
                )),
                Button("Add to Cart", cls=combine_classes(
                    btn,
                    btn_colors.primary,
                    btn_sizes.sm
                )),
                cls=combine_classes(card_actions, justify.between, items.center)
            ),
            cls=str(card_body)
        ),
        cls=combine_classes(card, shadow.md, bg_dui.base_100)
    )

# Usage - clean and simple
ProductCard(
    title="Premium Widget",
    description="High-quality widget with advanced features...",
    price="29.99",
    image_url="/images/widget.jpg"
)
```

The libraries provide the type-safe foundation; you build the components that make sense for your application.

## Common Design Patterns

### Card with Good Hierarchy
```python
from fasthtml.common import Card, Div, H2, P, Button
from cjm_fasthtml_daisyui.components.data_display.card import card, card_body, card_title, card_actions
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_styles, btn_colors
from cjm_fasthtml_daisyui.utilities.semantic_colors import bg_dui, text_dui
from cjm_fasthtml_tailwind.utilities.typography import font_size, font_weight, leading
from cjm_fasthtml_tailwind.utilities.flexbox_and_grid import justify, gap
from cjm_fasthtml_tailwind.utilities.effects import shadow
from cjm_fasthtml_tailwind.core.base import combine_classes

card_example = Card(
    Div(
        H2("Card Title", cls=combine_classes(
            card_title,
            font_size._2xl,
            font_weight.bold,
            text_dui.base_content  # Use semantic color
        )),
        P("Supporting text with less emphasis", cls=combine_classes(
            text_dui.base_content.opacity(70),  # Faded semantic color
            leading.relaxed
        )),
        Div(
            Button("Cancel", cls=combine_classes(btn, btn_styles.ghost)),
            Button("Confirm", cls=combine_classes(btn, btn_colors.primary)),
            cls=combine_classes(card_actions, justify.end, gap(2))
        ),
        cls=str(card_body)
    ),
    cls=combine_classes(card, shadow.md, bg_dui.base_100)
)
```

### Form with Visual Hierarchy
```python
from fasthtml.common import Form, Div, Label, Input, P, Button
from cjm_fasthtml_daisyui.components.data_input.text_input import text_input, text_input_sizes
from cjm_fasthtml_daisyui.components.actions.button import btn, btn_colors, btn_modifiers
from cjm_fasthtml_daisyui.utilities.semantic_colors import text_dui
from cjm_fasthtml_tailwind.utilities.spacing import space
from cjm_fasthtml_tailwind.utilities.sizing import w, max_w
from cjm_fasthtml_tailwind.utilities.typography import font_weight, font_size
from cjm_fasthtml_tailwind.utilities.effects import shadow
from cjm_fasthtml_tailwind.core.base import combine_classes

form_example = Form(
    Div(
        Label("Email Address", cls=combine_classes(
            font_weight.medium,
            text_dui.base_content  # Semantic color for labels
        )),
        Input(
            type="email",
            cls=combine_classes(
                text_input,
                text_input_sizes.md,
                w.full
            )
        ),
        P("We'll never share your email", cls=combine_classes(
            font_size.sm,
            text_dui.base_content.opacity(60)  # Faded for helper text
        )),
        cls=str(space.y(2))
    ),
    Button(
        "Submit",
        cls=combine_classes(
            btn,
            btn_colors.primary,
            btn_modifiers.block,
            shadow.md
        )
    ),
    cls=combine_classes(space.y(6), max_w.lg)
)
```

## Key Reminders

- **MANDATORY**: Always test code with `test-code` before implementation
- **FastHTML Examples Available**: Every module has `_fasthtml` examples - use them!
  - DaisyUI: `cjm-daisyui-explore example <module> <name>_fasthtml`
  - Tailwind: `cjm-tailwind-explore example <module> fasthtml`
- **Combine classes**: Use `combine_classes()` from `cjm_fasthtml_tailwind.core.base`
- **FastHTML integration**: Classes go in the `cls` parameter of FastHTML components
- **Both libraries work together**: Can combine DaisyUI components with Tailwind utilities
- **CLI is authoritative**: When in doubt, use the CLI tools to verify
- **Design with intention**: Apply Refactoring UI principles for professional results
- **State and responsive**: Both libraries support `.hover`, `.focus`, `.md`, `.lg` modifiers
- **Visual hierarchy matters**: Use size, weight, color, and spacing to guide the eye