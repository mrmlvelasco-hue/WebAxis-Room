document.addEventListener("DOMContentLoaded", function () {

    console.log("reserve_submit loaded");

    const submitBtn = document.getElementById("submitBtn");

    if (!submitBtn) return;

    submitBtn.addEventListener("click", async function (e) {

        e.preventDefault();

        const startInput = document.getElementById("modalStartTime");
        const endInput = document.getElementById("modalEndTime");
        const remarksInput = document.getElementById("modalMeetingTitle");
        const dateInput = document.getElementById("modalDate");

        if (!startInput.value || !endInput.value) {

            Swal.fire(
                "Missing Data",
                "Please select start and end time.",
                "warning"
            );

            return;
        }

        function toMinutes(t) {

            const [h, m] = t.split(":").map(Number);

            return h * 60 + m;

        }

        if (toMinutes(endInput.value) <= toMinutes(startInput.value)) {

            Swal.fire(
                "Invalid Time",
                "End must be after start.",
                "error"
            );

            return;
        }

        /* =====================================
           FIND ROOM
        ===================================== */

        const roomName =
            document.getElementById("modalRoomLabel")
            ?.textContent
            ?.trim();

        const room = ROOMS.find(r => r.name === roomName);

        if (!room) {

            Swal.fire("Error", "Room not found.", "error");

            return;
        }

        if (!dateInput.value) {

            Swal.fire("Missing Date",
                "Please select a date.",
                "warning");

            return;
        }

        /* =====================================
           BUILD PAYLOAD
        ===================================== */

        const startCombined =
            `${dateInput.value}T${startInput.value}`;

        const endCombined =
            `${dateInput.value}T${endInput.value}`;

        const fd = new FormData();

        fd.append("start_time", startCombined);
        fd.append("end_time", endCombined);

        fd.append("remarks", remarksInput.value || "");

        fd.append(
            "recurrence_type",
            document.getElementById("repeat_rule")?.value || "none"
        );

        const selectedWeekdays = Array.from(
            document.querySelectorAll(".wkday:checked")
        ).map(cb => cb.value);

        fd.append("weekdays", selectedWeekdays.join(","));

        fd.append(
            "weekly_interval",
            document.getElementById("weeklyInterval")?.value || 1
        );

        let endMode = "never";

        if (document.getElementById("endsOn")?.checked) endMode = "on";
        if (document.getElementById("endsAfter")?.checked) endMode = "after";

        fd.append("end_mode", endMode);

        fd.append(
            "end_on_date",
            document.getElementById("endsOnDate")?.value || ""
        );

        fd.append(
            "end_after_count",
            document.getElementById("endsAfterCount")?.value || ""
        );

        submitBtn.disabled = true;

        const originalText = submitBtn.innerHTML;

        submitBtn.innerHTML =
            `<span class="spinner-border spinner-border-sm"></span> Saving...`;

        try {

            const res = await fetch(`/reserve_post/${room.id}`, {
                method: "POST",
                body: fd,
                headers: { "X-Requested-With": "XMLHttpRequest" }
            });

            const data = await res.json();

            /* =====================================
               SUCCESS
            ===================================== */

            if (res.ok && data.success) {

                const modalInstance =
                    bootstrap.Modal.getInstance(
                        document.getElementById("reserveModal")
                    );

                if (modalInstance) modalInstance.hide();

                setTimeout(() => {
                    refreshAvailability();
                }, 200);

                await Swal.fire(
                    "Success",
                    "Reservation created.",
                    "success"
                );

                return;
            }

            /* =====================================
               CONFLICT
            ===================================== */

            if (res.status === 409 && data.conflicts) {

                let html = `
                <div style="text-align:left;">
                <b style="color:#dc3545;">
                ${data.conflicts.length} conflict(s) detected
                </b><br><br>`;

                data.conflicts.forEach(c => {

                    html += `
                    <div style="margin-bottom:10px;">
                        <b>${c.date}</b><br>
                        ${c.conflict_with}<br>
                        ${c.time_range}
                    </div>`;

                });

                html += `No reservations were saved.</div>`;

                await Swal.fire({
                    icon: "error",
                    title: "Reservation Conflict",
                    html: html,
                    width: 600
                });

                return;
            }

            throw new Error(data.message || "Reservation failed.");

        } catch (err) {

            await Swal.fire(
                "Error",
                err.message || "Unexpected system error.",
                "error"
            );

        } finally {

            submitBtn.disabled = false;

            submitBtn.innerHTML = originalText;

        }

    });

});