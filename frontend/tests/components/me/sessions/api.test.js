import axios from "axios";
import { addToast } from "@certego/certego-ui";

import {
  deleteOtherSessions,
  deleteTokenById,
} from "../../../../src/components/me/sessions/api";
import { SESSIONS_BASE_URI } from "../../../../src/constants/api";

vi.mock("axios");
vi.mock("@certego/certego-ui", () => ({
  addToast: vi.fn(),
}));

describe("sessions api helpers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("deleteTokenById calls endpoint and shows success toast", async () => {
    axios.delete.mockResolvedValue({ status: 204 });

    await deleteTokenById(42, "Firefox");

    expect(axios.delete).toHaveBeenCalledWith(`${SESSIONS_BASE_URI}/42`);
    expect(addToast).toHaveBeenCalledWith(
      "Revoked Session (Firefox).",
      null,
      "success",
      true,
      6000,
    );
  });

  test("deleteTokenById rejects and shows failure toast", async () => {
    const error = { parsedMsg: "cannot revoke" };
    axios.delete.mockRejectedValue(error);

    await expect(deleteTokenById(9, "Safari")).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "cannot revoke",
      "danger",
      true,
    );
  });

  test("deleteOtherSessions calls /others endpoint and shows success toast", async () => {
    axios.delete.mockResolvedValue({ status: 204 });

    await deleteOtherSessions();

    expect(axios.delete).toHaveBeenCalledWith(`${SESSIONS_BASE_URI}/others`);
    expect(addToast).toHaveBeenCalledWith(
      "Revoked all other sessions.",
      null,
      "success",
      true,
      6000,
    );
  });

  test("deleteOtherSessions rejects and shows failure toast", async () => {
    const error = { parsedMsg: "backend error" };
    axios.delete.mockRejectedValue(error);

    await expect(deleteOtherSessions()).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "backend error",
      "danger",
      true,
    );
  });
});
