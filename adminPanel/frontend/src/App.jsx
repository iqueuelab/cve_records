import CVEList from "./components/CVEList";

export default function App() {
  return (
    <div className="app">
      <header>
        <h1>CVE History</h1>
      </header>
      <main>
        <CVEList />
      </main>
    </div>
  );
}
