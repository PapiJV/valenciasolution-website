// Single source of truth for the paid Notepad apps. Server-only: these URLs
// are never shipped in page HTML, and every link handed out carries a signed
// licence in the URL hash (#license=...), which the app verifies offline.

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

// Live Stripe Payment Links -> app. Tier comes from the price actually paid.
export const PAYMENT_LINKS = {
  plink_1U7ba32acRxanCPyPHUNESmJ: "basketball",
  plink_1U7bZz2acRxanCPySLP3eEAI: "basketball",
  plink_1U7bSF2acRxanCPySNOXbndU: "volleyball",
  plink_1U7bSB2acRxanCPyn3IDc9Jr: "volleyball",
  plink_1U7bSL2acRxanCPyKGogs3Mn: "football",
  plink_1U7bSI2acRxanCPy9XOcaJqq: "football",
  plink_1U7bSd2acRxanCPyskm1eq7G: "lacrosse",
  plink_1U7bSP2acRxanCPykpLkOkUM: "lacrosse",
  plink_1UOmOY2acRxanCPyI6PphkQt: "baseball",
  plink_1UOmOS2acRxanCPyTyLrOAJq: "baseball",
  plink_1UJBCJ2acRxanCPyJKgT3DEp: "baseball",
  plink_1UJBCA2acRxanCPydfbR8oKX: "baseball",
  plink_1UOmOZ2acRxanCPyjNYV9zaN: "curling",
  plink_1UOmOZ2acRxanCPySYmKGBC6: "curling",
  plink_1UJBCO2acRxanCPyRPCpdEYp: "curling",
  plink_1UJBCL2acRxanCPyJ1h05UpX: "curling",
  plink_1UJBCS2acRxanCPyQHVaiII0: "hockey",
  plink_1UJBCQ2acRxanCPyfEBQH4c5: "hockey",
  plink_1UJBCW2acRxanCPySeXwhCPh: "cricket",
  plink_1UJBCU2acRxanCPyV5BwBww7: "cricket",
  plink_1UJBCb2acRxanCPyYqAGljG1: "soccer",
  plink_1UJBCZ2acRxanCPy6vJKvzKc: "soccer",
  plink_1UJBCf2acRxanCPyUN66h5Hs: "rugby",
  plink_1UJBCd2acRxanCPyKx6hzsDO: "rugby",
};

export const CLUB_MIN_CENTS = 20000; // anything >= CA$200 pre-tax is the club tier

export function appLink(app, token) {
  return `${APPS[app].url}#license=${token}`;
}
