package io.deltator.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.deltator.core.chain.ChainOrchestrator
import io.deltator.core.chain.HopSpec
import io.deltator.core.chain.MultiHopPlan
import io.deltator.core.chain.TransportHopType

@Composable
fun ChainBuilderScreen(
    onBack: () -> Unit,
    onApplyChain: (MultiHopPlan) -> Unit
) {
    var selectedPlan by remember { mutableStateOf(ChainOrchestrator.PRESET_AWG_TOR) }
    var currentHops by remember { mutableStateOf(selectedPlan.hops.toMutableList()) }

    val calculatedMtu = remember(currentHops) {
        var mtu = 1500
        for (h in currentHops) {
            mtu -= h.type.mtuOverhead
        }
        mtu.coerceAtLeast(1280)
    }

    // Live validation warnings
    val warnings = remember(currentHops) {
        val list = mutableListOf<String>()
        val types = currentHops.map { it.type }
        for (i in 0 until types.size - 1) {
            if (types[i] == TransportHopType.TOR && types[i + 1] == TransportHopType.TOR) {
                list.add("Tor → Tor adds significant latency without increasing anonymity")
            }
            if (types[i] == TransportHopType.TOR && (types[i + 1] == TransportHopType.AMNEZIA_WG || types[i + 1] == TransportHopType.WARP)) {
                list.add("Tor is TCP-only; UDP traffic to ${types[i+1].title} requires a UoT relay or MASQUE H2 bridge")
            }
        }
        list
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0F1117))
            .padding(16.dp)
    ) {
        // Top Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onBack) {
                Text("← Back", color = Color(0xFF7AA2F7), fontSize = 16.sp)
            }
            Text("Chain Builder", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Button(
                onClick = {
                    val finalPlan = MultiHopPlan(name = selectedPlan.name, hops = currentHops)
                    onApplyChain(finalPlan)
                    onBack()
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7AA2F7)),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Apply", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Preset selector
        Text("Popular Presets", color = Color(0xFFA9B1D6), fontSize = 14.sp)
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ChainOrchestrator.ALL_PRESETS.take(3).forEach { preset ->
                val isSelected = preset.name == selectedPlan.name
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (isSelected) Color(0xFF1E2A4A) else Color(0xFF1A1B26),
                            RoundedCornerShape(8.dp)
                        )
                        .border(
                            1.dp,
                            if (isSelected) Color(0xFF7AA2F7) else Color(0xFF2E3244),
                            RoundedCornerShape(8.dp)
                        )
                        .clickable {
                            selectedPlan = preset
                            currentHops = preset.hops.toMutableList()
                        }
                        .padding(vertical = 10.dp, horizontal = 6.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        preset.name,
                        color = if (isSelected) Color.White else Color(0xFFA9B1D6),
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ChainOrchestrator.ALL_PRESETS.drop(3).take(3).forEach { preset ->
                val isSelected = preset.name == selectedPlan.name
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (isSelected) Color(0xFF1E2A4A) else Color(0xFF1A1B26),
                            RoundedCornerShape(8.dp)
                        )
                        .border(
                            1.dp,
                            if (isSelected) Color(0xFF7AA2F7) else Color(0xFF2E3244),
                            RoundedCornerShape(8.dp)
                        )
                        .clickable {
                            selectedPlan = preset
                            currentHops = preset.hops.toMutableList()
                        }
                        .padding(vertical = 10.dp, horizontal = 6.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        preset.name,
                        color = if (isSelected) Color.White else Color(0xFFA9B1D6),
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // MTU & Chain Info Banner
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF16161E), RoundedCornerShape(8.dp))
                .border(1.dp, Color(0xFF24283B), RoundedCornerShape(8.dp))
                .padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Dynamic MTU: $calculatedMtu", color = Color(0xFF9ECE6A), fontWeight = FontWeight.SemiBold)
                Text("${currentHops.size} / 4 Hops", color = Color(0xFFA9B1D6))
            }
        }

        // Warnings banner if any
        if (warnings.isNotEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF3B2D20), RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                warnings.forEach { w ->
                    Text("⚠️ $w", color = Color(0xFFE0AF68), fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text("Configured Hops", color = Color(0xFFA9B1D6), fontSize = 14.sp)
        Spacer(modifier = Modifier.height(8.dp))

        // Hops list
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            itemsIndexed(currentHops) { index, hop ->
                val isEntry = (index == 0)
                val isExit = (index == currentHops.size - 1)
                val roleLabel = when {
                    isEntry && isExit -> "Standalone"
                    isEntry -> "Entry (Hop 0)"
                    isExit -> "Exit (Hop ${currentHops.size - 1})"
                    else -> "Middle (Hop $index)"
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1B26)),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                "${index + 1}. ${hop.type.title}",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                            Text(
                                roleLabel,
                                color = if (isExit) Color(0xFF7AA2F7) else Color(0xFF565F89),
                                fontSize = 12.sp
                            )
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            if (index > 0) {
                                TextButton(
                                    onClick = {
                                        val mutable = currentHops.toMutableList()
                                        val temp = mutable[index]
                                        mutable[index] = mutable[index - 1]
                                        mutable[index - 1] = temp
                                        currentHops = mutable
                                    }
                                ) {
                                    Text("↑", color = Color.White, fontSize = 16.sp)
                                }
                            }
                            if (index < currentHops.size - 1) {
                                TextButton(
                                    onClick = {
                                        val mutable = currentHops.toMutableList()
                                        val temp = mutable[index]
                                        mutable[index] = mutable[index + 1]
                                        mutable[index + 1] = temp
                                        currentHops = mutable
                                    }
                                ) {
                                    Text("↓", color = Color.White, fontSize = 16.sp)
                                }
                            }
                            if (currentHops.size > 1) {
                                TextButton(
                                    onClick = {
                                        val mutable = currentHops.toMutableList()
                                        mutable.removeAt(index)
                                        currentHops = mutable
                                    }
                                ) {
                                    Text("✕", color = Color(0xFFF7768E), fontSize = 16.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
