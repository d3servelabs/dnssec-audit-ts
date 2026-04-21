import { render } from "preact";
import { App } from "./app.tsx";
import "@namefi/dnssec-ui-shared/styles.css";

const root = document.getElementById("app");
if (root) render(<App />, root);
