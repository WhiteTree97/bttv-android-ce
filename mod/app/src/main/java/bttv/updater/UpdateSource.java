package bttv.updater;

/** Release trust boundary. The local metadata tool reads this same repository literal. */
public final class UpdateSource {
    public static final String REPOSITORY = "WhiteTree97/bttv-android-ce";
    public static final int PER_PAGE = 10, MAX_PAGES = 3;

    private UpdateSource() { }

    public static String releasesPage(int page) {
        if (page < 1 || page > MAX_PAGES) throw new IllegalArgumentException("Invalid release page");
        return "https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=" + PER_PAGE + "&page=" + page;
    }

    static boolean metadataUrl(String value) {
        for (int page = 1; page <= MAX_PAGES; page++) if (releasesPage(page).equals(value)) return true;
        return false;
    }

    public static String downloadPrefix() {
        return "https://github.com/" + REPOSITORY + "/releases/download/";
    }
}
