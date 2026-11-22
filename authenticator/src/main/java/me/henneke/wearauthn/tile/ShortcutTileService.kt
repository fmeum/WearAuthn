package me.henneke.wearauthn.tile

import android.annotation.SuppressLint
import android.content.ComponentName
import androidx.wear.protolayout.ActionBuilders
import androidx.wear.protolayout.ColorBuilders
import androidx.wear.protolayout.DimensionBuilders
import androidx.wear.protolayout.LayoutElementBuilders
import androidx.wear.protolayout.LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER
import androidx.wear.protolayout.LayoutElementBuilders.TEXT_OVERFLOW_ELLIPSIZE_END
import androidx.wear.protolayout.LayoutElementBuilders.VERTICAL_ALIGN_CENTER
import androidx.wear.protolayout.ModifiersBuilders
import androidx.wear.protolayout.ResourceBuilders
import androidx.wear.protolayout.TimelineBuilders
import androidx.wear.protolayout.TypeBuilders
import androidx.wear.tiles.RequestBuilders
import androidx.wear.tiles.TileBuilders
import androidx.wear.tiles.TileService
import com.google.common.util.concurrent.ListenableFuture
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.identifier
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

private const val RESOURCES_VERSION = "1"
private const val ICON_RESOURCE_ID = "shortcut_icon"
private const val ICON_PHONE_RESOURCE_ID = "shortcut_icon_phone"
private const val FRESHNESS_MILLIS = 15L * 60L * 1000L

// Wear Material 3 Expressive tile, hand-built because tiles 1.4.1 / protolayout 1.2.0 predate the
// M3 helpers: a single tonal card holding the host; the whole tile is the tap target.
private const val CARD_HEIGHT_DP = 96f
private const val CARD_RADIUS_DP = 24f
private const val CHIP_SIZE_DP = 40f

private const val COLOR_SURFACE = 0xFF1B1C21.toInt()
private const val COLOR_GREEN = 0xFF3DDC84.toInt()
private const val COLOR_PRIMARY_CONTAINER = 0xFF2962FF.toInt()
private const val COLOR_ON_PRIMARY_CONTAINER = 0xFFFFFFFF.toInt()
private const val COLOR_ON_SURFACE = 0xFFEDEDF0.toInt()
private const val COLOR_ON_SURFACE_VARIANT = 0xFFB9BBC4.toInt()

/**
 * Completes immediately with the given value. Equivalent to Guava's Futures.immediateFuture,
 * but keeps the full Guava artifact out of the APK.
 */
private class DoneFuture<T>(private val value: T) : ListenableFuture<T> {
    override fun addListener(listener: Runnable, executor: Executor) {
        executor.execute(listener)
    }

    override fun cancel(mayInterruptIfRunning: Boolean): Boolean = false
    override fun isCancelled(): Boolean = false
    override fun isDone(): Boolean = true
    override fun get(): T = value
    override fun get(timeout: Long, unit: TimeUnit): T = value
}

/**
 * Tile counterpart of the watch face shortcut: a one-swipe, one-tap entry point that does not
 * depend on the (legacy) complications API being supported by the active watch face.
 */
class ShortcutTileService : TileService() {

    override fun onTileRequest(
        requestParams: RequestBuilders.TileRequest
    ): ListenableFuture<TileBuilders.Tile> {
        val timeline = TimelineBuilders.Timeline.Builder()
            .addTimelineEntry(
                TimelineBuilders.TimelineEntry.Builder()
                    .setLayout(
                        LayoutElementBuilders.Layout.Builder()
                            .setRoot(tileLayout())
                            .build()
                    )
                    .build()
            )
            .build()

        return DoneFuture(
            TileBuilders.Tile.Builder()
                .setResourcesVersion(RESOURCES_VERSION)
                .setFreshnessIntervalMillis(FRESHNESS_MILLIS)
                .setTileTimeline(timeline)
                .build()
        )
    }

    override fun onTileResourcesRequest(
        requestParams: RequestBuilders.ResourcesRequest
    ): ListenableFuture<ResourceBuilders.Resources> =
        DoneFuture(
            ResourceBuilders.Resources.Builder()
                .setVersion(RESOURCES_VERSION)
                .addIdToImageMapping(
                    ICON_RESOURCE_ID,
                    ResourceBuilders.ImageResource.Builder()
                        .setAndroidResourceByResId(
                            ResourceBuilders.AndroidImageResourceByResId.Builder()
                                .setResourceId(R.drawable.ic_computer)
                                .build()
                        )
                        .build()
                )
                .addIdToImageMapping(
                    ICON_PHONE_RESOURCE_ID,
                    ResourceBuilders.ImageResource.Builder()
                        .setAndroidResourceByResId(
                            ResourceBuilders.AndroidImageResourceByResId.Builder()
                                .setResourceId(R.drawable.ic_phone)
                                .build()
                        )
                        .build()
                )
                .build()
        )

    private fun tileLayout(): LayoutElementBuilders.LayoutElement {
        // The label and the tap both go through the same resolver, so the tile never promises
        // one host while the tap attaches to another.
        val device = resolveShortcutDevice()
        val headline = device?.identifier ?: getString(R.string.tile_main_choose)
        val hint = if (device != null) {
            getString(R.string.tile_hint_attach)
        } else {
            getString(R.string.tile_subtitle_choose_device)
        }
        val isPhone = device?.let { isPhone(it) } ?: false

        val iconChip = LayoutElementBuilders.Box.Builder()
            .setWidth(DimensionBuilders.dp(CHIP_SIZE_DP))
            .setHeight(DimensionBuilders.dp(CHIP_SIZE_DP))
            .setHorizontalAlignment(HORIZONTAL_ALIGN_CENTER)
            .setVerticalAlignment(VERTICAL_ALIGN_CENTER)
            .addContent(
                LayoutElementBuilders.Image.Builder()
                    .setResourceId(if (isPhone) ICON_PHONE_RESOURCE_ID else ICON_RESOURCE_ID)
                    .setWidth(DimensionBuilders.dp(22f))
                    .setHeight(DimensionBuilders.dp(22f))
                    .setContentScaleMode(LayoutElementBuilders.CONTENT_SCALE_MODE_FIT)
                    .setColorFilter(
                        LayoutElementBuilders.ColorFilter.Builder()
                            .setTint(ColorBuilders.argb(COLOR_ON_PRIMARY_CONTAINER))
                            .build()
                    )
                    .build()
            )
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setBackground(
                        ModifiersBuilders.Background.Builder()
                            .setColor(ColorBuilders.argb(COLOR_PRIMARY_CONTAINER))
                            .setCorner(
                                ModifiersBuilders.Corner.Builder()
                                    .setRadius(DimensionBuilders.dp(CHIP_SIZE_DP / 2f))
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()

        // Card content is a column: mark, host, then the state line. Nothing is wider than the
        // circle chord at this height, so the name never gets sliced by the bezel.
        val cardContent = LayoutElementBuilders.Column.Builder()
            .setWidth(DimensionBuilders.expand())
            .setHorizontalAlignment(HORIZONTAL_ALIGN_CENTER)
            .addContent(iconChip)
            .addContent(
                LayoutElementBuilders.Spacer.Builder()
                    .setHeight(DimensionBuilders.dp(4f))
                    .build()
            )
            .addContent(
                text(
                    value = headline,
                    sizeSp = 16f,
                    weight = LayoutElementBuilders.FONT_WEIGHT_BOLD,
                    color = COLOR_ON_SURFACE,
                    maxLines = 1,
                    overflow = TEXT_OVERFLOW_ELLIPSIZE_END
                )
            )
            .addContent(
                LayoutElementBuilders.Spacer.Builder()
                    .setHeight(DimensionBuilders.dp(2f))
                    .build()
            )
            .addContent(
                text(
                    value = hint,
                    sizeSp = 11f,
                    weight = LayoutElementBuilders.FONT_WEIGHT_NORMAL,
                    color = if (device != null) COLOR_GREEN else COLOR_ON_SURFACE_VARIANT,
                    maxLines = 1,
                    overflow = TEXT_OVERFLOW_ELLIPSIZE_END
                )
            )
            .build()

        val card = LayoutElementBuilders.Box.Builder()
            .setWidth(DimensionBuilders.expand())
            .setHeight(DimensionBuilders.dp(CARD_HEIGHT_DP))
            .setHorizontalAlignment(HORIZONTAL_ALIGN_CENTER)
            .setVerticalAlignment(VERTICAL_ALIGN_CENTER)
            .addContent(cardContent)
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setBackground(
                        ModifiersBuilders.Background.Builder()
                            .setColor(ColorBuilders.argb(COLOR_SURFACE))
                            .setCorner(
                                ModifiersBuilders.Corner.Builder()
                                    .setRadius(DimensionBuilders.dp(CARD_RADIUS_DP))
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()

        val column = LayoutElementBuilders.Column.Builder()
            .setWidth(DimensionBuilders.expand())
            .addContent(card)
            .build()

        // 20dp sides keep the card's corners inside the bezel chord at this height.
        return LayoutElementBuilders.Box.Builder()
            .setWidth(DimensionBuilders.expand())
            .setHeight(DimensionBuilders.expand())
            .setVerticalAlignment(VERTICAL_ALIGN_CENTER)
            .addContent(column)
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setPadding(
                        ModifiersBuilders.Padding.Builder()
                            .setStart(DimensionBuilders.dp(20f))
                            .setEnd(DimensionBuilders.dp(20f))
                            .setTop(DimensionBuilders.dp(4f))
                            .setBottom(DimensionBuilders.dp(4f))
                            .build()
                    )
                    .setClickable(
                        ModifiersBuilders.Clickable.Builder()
                            .setOnClick(clickAction())
                            .setId("shortcut_tile")
                            .build()
                    )
                    .build()
            )
            .build()
    }

    private fun text(
        value: String,
        sizeSp: Float,
        weight: Int,
        color: Int,
        maxLines: Int = 1,
        overflow: Int = LayoutElementBuilders.TEXT_OVERFLOW_TRUNCATE
    ): LayoutElementBuilders.Text = LayoutElementBuilders.Text.Builder()
        .setText(TypeBuilders.StringProp.Builder(value).build())
        .setFontStyle(
            LayoutElementBuilders.FontStyle.Builder()
                .setSize(DimensionBuilders.sp(sizeSp))
                .setWeight(weight)
                .setColor(ColorBuilders.argb(color))
                .build()
        )
        .setMaxLines(maxLines)
        .setOverflow(overflow)
        .build()

    @SuppressLint("MissingPermission")
    private fun isPhone(device: android.bluetooth.BluetoothDevice): Boolean =
        try {
            device.bluetoothClass?.majorDeviceClass == android.bluetooth.BluetoothClass.Device.Major.PHONE
        } catch (e: SecurityException) {
            false
        }

    private fun clickAction(): ActionBuilders.Action =
        ActionBuilders.launchAction(
            ComponentName(this, ShortcutLaunchActivity::class.java)
        )
}
