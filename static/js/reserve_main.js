function refreshAvailability() {

    const locationFilter = document.getElementById("locationFilterHeader");
    const roomFilter = document.getElementById("roomFilterHeader");
    const viewDateInput = document.getElementById("viewDate");

    const loc = locationFilter?.value || "all";
    const room = roomFilter?.value || "all";
    const selectedDate = viewDateInput?.value;

    if (!selectedDate) return;

    const url =
        `/calendar_view_v2?embed=1`
        + `&date=${encodeURIComponent(selectedDate)}`
        + `&location=${encodeURIComponent(loc)}`
        + `&room=${encodeURIComponent(room)}`;

    const frame = document.getElementById("availabilityFrame");

    if (!frame) return;

    frame.src = url;
}
document.addEventListener("DOMContentLoaded", function () {

    console.log("reserve_main loaded");

    const modalEl = document.getElementById("reserveModal");

    const locationFilter = document.getElementById("locationFilterHeader");
    const roomFilter = document.getElementById("roomFilterHeader");
    const applyBtn = document.getElementById("applyFilterBtn");
    const iframe = document.getElementById("availabilityFrame");

    const viewDate = document.getElementById("viewDate");

    if (viewDate) {
        viewDate.value = new Date().toISOString().split("T")[0];
    }

    if (roomFilter) {
        roomFilter.disabled = true;
    }

    refreshAvailability();

    /* =====================================================
       HEADER LOCATION FILTER
    ===================================================== */

    if (locationFilter) {

        locationFilter.addEventListener("change", function () {

            const loc = this.value;

            roomFilter.innerHTML = `<option value="all">All Rooms</option>`;

            roomFilter.disabled = false;

            const filteredRooms = ROOMS.filter(r =>
                loc === "all" || (r.location || "General") === loc
            );

            filteredRooms.forEach(r => {

                const opt = document.createElement("option");
                opt.value = r.name;
                opt.textContent = r.name;

                roomFilter.appendChild(opt);

            });

        });

    }

    /* =====================================================
       APPLY FILTER BUTTON
    ===================================================== */

    if (applyBtn) {

        applyBtn.addEventListener("click", function () {

            const loc = locationFilter?.value || "all";
            const room = roomFilter?.value || "all";
            const selectedDate = viewDate?.value;

            iframe.src =
                `/calendar_view_v2?embed=1`
                + `&date=${encodeURIComponent(selectedDate)}`
                + `&location=${encodeURIComponent(loc)}`
                + `&room=${encodeURIComponent(room)}`;

        });

    }

    /* =====================================================
       GRID MESSAGE EVENTS
    ===================================================== */

    window.addEventListener("message", function (event) {

        if (!event.data || !event.data.type) return;

        /* ================================
           OPEN NEW RESERVATION
        ================================ */

        if (event.data.type === "OPEN_NEW_RESERVATION") {

            const source = event.data.source || "grid";

            const selectedDate = document.getElementById("viewDate")?.value;

            if (source === "quick") {

                document.getElementById("modalDate").value = selectedDate;

                document.getElementById("modalRoomLabel").textContent = "Select Room";

                new bootstrap.Modal(modalEl).show();

                return;
            }

            const roomId = event.data.room_id;
            const slotMin = event.data.slot_min;

            const room = ROOMS.find(r => r.id == roomId);

            if (!room) return;

            const hours = String(Math.floor(slotMin / 60)).padStart(2, "0");
            const minutes = String(slotMin % 60).padStart(2, "0");

            const startTime = `${hours}:${minutes}`;

            const endDate = new Date(`${selectedDate}T${startTime}`);
            endDate.setMinutes(endDate.getMinutes() + 30);

            const endTime =
                String(endDate.getHours()).padStart(2, "0")
                + ":"
                + String(endDate.getMinutes()).padStart(2, "0");

            document.getElementById("modalDate").value = selectedDate;

            document.getElementById("modalStartTime").value = startTime;
            document.getElementById("modalEndTime").value = endTime;

            document.getElementById("modalRoomLabel").textContent = room.name;

            new bootstrap.Modal(modalEl).show();

        }

        /* ================================
           SHOW RESERVATION DETAILS
        ================================ */

        if (event.data.type === "SHOW_RESERVATION") {

            const res = event.data.data;

            showReservationDetails(res);

        }

    });

});