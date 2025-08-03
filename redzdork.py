import time
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium_stealth import stealth
from webdriver_manager.chrome import ChromeDriverManager

MAX_VALID = 5

def load_dorks(file_path="dork.txt"):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def setup_browser():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    browser = webdriver.Chrome(ChromeDriverManager().install(), options=options)

    # Stealth mode
    stealth(browser,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
    )
    return browser

def google_search(dork, browser):
    search_url = f"https://www.google.com/search?q={dork}"
    browser.get(search_url)
    time.sleep(2)

    results = browser.find_elements(By.XPATH, "//div[@class='yuRUbf']/a")
    return [r.get_attribute('href') for r in results]

def validate_link(url):
    try:
        r = requests.get(url, timeout=5)
        return r.status_code == 200
    except:
        return False

def main():
    print("🧠 RedzDork v3 Stealth Mode Activated 😈")
    dorks = load_dorks()
    browser = setup_browser()
    valid_count = 0
    printed = set()

    for dork in dorks:
        print(f"\n🔍 Dork: {dork}")
        links = google_search(dork, browser)

        for link in links:
            if link not in printed:
                print("⏳ Cek:", link)
                if validate_link(link):
                    print("✅ VALID:", link)
                    with open("hasil_valid.txt", "a") as f:
                        f.write(link + "\n")
                    valid_count += 1
                    printed.add(link)
                    if valid_count >= MAX_VALID:
                        print("\n🎉 DONE! Dapet 5 link valid 😎")
                        browser.quit()
                        return

    browser.quit()
    print("\n⚠️ Selesai tapi cuma dapet", valid_count, "link valid.")

if __name__ == "__main__":
    main()
