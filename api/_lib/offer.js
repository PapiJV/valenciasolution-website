// Free Notepad launch offer settings, shared by /api/register (which
// enforces them) and /api/signups (the admin view).

export const OFFER_ENDS_AT = "2027-01-01T04:59:59Z"; // Dec 31, 2026 11:59:59 pm Toronto (EST)
export const OFFER_CAP = 1000;

export const APPS = {
  basketball: { name: "Basketball Notepad", url: "https://basketball-notepad.vercel.app/" },
  volleyball: { name: "Volleyball Notepad", url: "https://volleyball-notepad.vercel.app/" },
  football: { name: "Football Notepad", url: "https://football-notepad.vercel.app/" },
  lacrosse: { name: "Lacrosse Notepad", url: "https://lacrosse-notepad.vercel.app/" },
  baseball: { name: "Baseball Notepad", url: "https://baseball-notepad.vercel.app/" },
  curling: { name: "Curling Notepad", url: "https://curling-notepad.vercel.app/" },
  hockey: { name: "Hockey Notepad", url: "https://hockey-notepad.vercel.app/" },
  cricket: { name: "Cricket Notepad", url: "https://cricket-notepad.vercel.app/" },
  soccer: { name: "Soccer Notepad", url: "https://soccer-notepad.vercel.app/" },
  rugby: { name: "Rugby Notepad", url: "https://rugby-notepad.vercel.app/" },
};

export const SPORTS = Object.keys(APPS);
