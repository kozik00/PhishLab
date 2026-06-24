import { NavLink, Outlet } from "react-router-dom";

export default function Layout() {
  return (
    <div className="app">
      <nav className="sidebar">
        <div className="sidebar-brand">
          <h1>PhishLab</h1>
          <span className="sidebar-subtitle">Email Threat Analysis</span>
        </div>
        <ul className="sidebar-nav">
          <li>
            <NavLink to="/" end>
              Analyze
            </NavLink>
          </li>
          <li>
            <NavLink to="/history">History</NavLink>
          </li>
          <li>
            <NavLink to="/training">Training</NavLink>
          </li>
        </ul>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
