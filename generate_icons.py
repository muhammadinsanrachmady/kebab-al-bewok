from PIL import Image, ImageDraw, ImageFont
import os

icons_dir = r"d:\2026\rachmady 2026\apk\kebab\backend\public\icons"
os.makedirs(icons_dir, exist_ok=True)

def create_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded rectangle background
    corner_radius = int(size * 0.22)
    bg_color = (220, 38, 38, 255) # Red #DC2626
    border_color = (251, 191, 36, 255) # Yellow #FBBF24

    # Draw rounded background
    draw.rounded_rectangle([(0, 0), (size, size)], radius=corner_radius, fill=bg_color)
    
    # Inner border
    pad = int(size * 0.05)
    border_width = max(2, int(size * 0.03))
    draw.rounded_rectangle([(pad, pad), (size - pad, size - pad)], radius=corner_radius - pad//2, outline=border_color, width=border_width)

    # Center circle for emblem
    center = size // 2
    emblem_radius = int(size * 0.28)
    draw.ellipse([(center - emblem_radius, center - emblem_radius - int(size * 0.05)),
                  (center + emblem_radius, center + emblem_radius - int(size * 0.05))],
                 fill=(245, 158, 11, 255), outline=border_color, width=border_width)

    # Text AL BEWOK
    # Approximate text using shapes or built-in font
    # Small kebab skewer graphic in center
    kw = int(size * 0.16)
    kh = int(size * 0.28)
    kx = center - kw // 2
    ky = center - kh // 2 - int(size * 0.05)
    
    # Draw simple kebab wrap
    draw.rounded_rectangle([(kx, ky), (kx + kw, ky + kh)], radius=kw//4, fill=(254, 243, 199, 255), outline=(180, 83, 9, 255), width=max(1, size//80))
    
    # Meat toppings on top of wrap
    draw.ellipse([(kx, ky - kw//3), (kx + kw, ky + kw//3)], fill=(127, 29, 29, 255))
    draw.ellipse([(kx + kw//4, ky - kw//2), (kx + 3*kw//4, ky)], fill=(22, 163, 74, 255))

    # Save
    out_path = os.path.join(icons_dir, f"icon-{size}.png")
    img.save(out_path, "PNG")
    print(f"Generated {out_path}")

create_icon(192)
create_icon(512)
print("Icons created successfully!")
