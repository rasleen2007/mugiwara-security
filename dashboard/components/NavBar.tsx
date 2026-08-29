import Link from "next/link";
import LogoutButton from "@/components/LogoutButton";

/**
 * Top navigation bar — Server Component rendered by the root layout.
 * Receives the (possibly null) user email from the layout's auth check.
 */

export default function NavBar({ userEmail }: { userEmail: string | null }) {
  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <Link href="/" className="navbar-brand">
          <span className="brand-mark">☠</span> Mugiwara Security
        </Link>
        <div className="flex items-center gap-4">
          {userEmail ? (
            <>
              <Link href="/dashboard" className="nav-link">
                Dashboard
              </Link>
              <span className="nav-user" title={userEmail}>
                {userEmail}
              </span>
              <LogoutButton />
            </>
          ) : (
            <>
              <a href="/#about" className="nav-link">
                About
              </a>
              <a href="/#features" className="nav-link">
                Features
              </a>
              <a href="/#how-it-works" className="nav-link">
                How It Works
              </a>
              <Link href="/demo" className="nav-link">
                Demo
              </Link>
              <Link href="/login" className="nav-link">
                Log In
              </Link>
              <Link href="/signup" className="btn btn-cta btn-sm">
                Sign Up
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}
