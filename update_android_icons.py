from PIL import Image
import os

source_icon = r"d:\2026\rachmady 2026\apk\kebab\backend\public\icons\icon-512.png"
res_dir = r"d:\2026\rachmady 2026\apk\kebab\android-app\android\app\src\main\res"

sizes = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192
}

img = Image.open(source_icon)

for folder, size in sizes.items():
    target_folder = os.path.join(res_dir, folder)
    os.makedirs(target_folder, exist_ok=True)
    
    # Square icon
    resized = img.resize((size, size), Image.Resampling.LANCZOS)
    resized.save(os.path.join(target_folder, "ic_launcher.png"), "PNG")
    
    # Round icon
    resized.save(os.path.join(target_folder, "ic_launcher_round.png"), "PNG")
    print(f"Updated icons for {folder} ({size}x{size})")

print("All Android app launcher icons updated with Kebab AL Bewok logo!")
