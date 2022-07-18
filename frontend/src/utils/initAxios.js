import axios from "axios";

export default function initAxios() {
    // base config
    axios.defaults.headers.common["Content-Type"] = "application/json";
    axios.defaults.withCredentials = false;
}